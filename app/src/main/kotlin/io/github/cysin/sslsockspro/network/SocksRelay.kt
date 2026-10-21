package io.github.cysin.sslsockspro.network

import io.github.cysin.sslsockspro.config.Endpoint
import io.github.cysin.sslsockspro.model.ProxyKind
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.IDN
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.ServerSocketChannel
import java.nio.channels.SocketChannel
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.Executors
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/** Authenticated local SOCKS5 and HTTP CONNECT frontend; the only client of
 * the stunnel listener in VPN modes. Transfers use one NIO reactor, not one
 * thread per stream. Its UDP socket accepts DNS only and never forwards UDP.
 * [ownerCheck] receives (peer, local) and admits only this app's sockets.
 */
class SocksRelay(
    private val upstream: Endpoint,
    private val kind: ProxyKind,
    private val ownerCheck: (InetSocketAddress, InetSocketAddress) -> Boolean = { _, _ -> true },
    private val dns: (ByteArray) -> ByteArray,
) : AutoCloseable {
    val username = "vpn"
    val password = UUID.randomUUID().toString().replace("-", "")
    private val selector = Selector.open()
    private val server = ServerSocketChannel.open().apply { bind(InetSocketAddress("127.0.0.1", 0)) }
    val port = (server.localAddress as InetSocketAddress).port
    private val udp = DatagramChannel.open().apply { bind(InetSocketAddress("127.0.0.1", 0)); configureBlocking(false); register(selector, SelectionKey.OP_READ, this) }
    private val udpPort = (udp.localAddress as InetSocketAddress).port
    private val slots = AtomicInteger()
    private val handshake = ThreadPoolExecutor(4, 4, 0, TimeUnit.SECONDS, LinkedBlockingQueue(124))
    private val upstreamHandshake = ThreadPoolExecutor(8, 8, 0, TimeUnit.SECONDS, LinkedBlockingQueue(120))
    private val dnsExecutor = ThreadPoolExecutor(4, 4, 0, TimeUnit.SECONDS, LinkedBlockingQueue(64))
    private val registrations = ConcurrentLinkedQueue<Any>()
    private val completions = ConcurrentLinkedQueue<() -> Unit>()
    private val channels = ConcurrentHashMap.newKeySet<SocketChannel>()
    private val associations = ConcurrentHashMap.newKeySet<UdpControl>()
    private val acceptor: Thread
    private val reactor: Thread
    @Volatile private var running = true
    val sent = AtomicLong()
    val received = AtomicLong()
    private val dnsRequests = AtomicLong()
    private val dnsResponses = AtomicLong()
    private val dnsFailures = AtomicLong()
    private val unassociatedUdp = AtomicLong()
    private val rejectedLocalClients = AtomicLong()
    private val basicAuthorization = "Basic " + java.util.Base64.getEncoder().encodeToString("$username:$password".toByteArray())
    fun diagnostics(): String = "DNS requests=${dnsRequests.get()} replies=${dnsResponses.get()} failures=${dnsFailures.get()}; " +
        "unassociated UDP=${unassociatedUdp.get()}; rejected local clients=${rejectedLocalClients.get()}; connections=${slots.get()} DNS workers=${dnsExecutor.activeCount} queued=${dnsExecutor.queue.size}; " +
        "authentication=${handshake.activeCount}/${handshake.queue.size} upstream=${upstreamHandshake.activeCount}/${upstreamHandshake.queue.size}"

    private class Session(val left: SocketChannel, val right: SocketChannel) {
        val leftToRight = ByteBuffer.allocate(32768)
        val rightToLeft = ByteBuffer.allocate(32768)
        var leftEof = false; var rightEof = false
        var leftShutdown = false; var rightShutdown = false
        var closed = false
    }
    private data class Side(val session: Session, val left: Boolean)
    private class UdpControl(val channel: SocketChannel, val sourcePort: Int) { var learnedPort = sourcePort; var closed = false }
    private class DnsConnection(val channel: SocketChannel) {
        val input = ByteBuffer.allocate(65537)
        var output: ByteBuffer? = null
        var pending = false
        var closed = false
        var lastActivity = System.nanoTime()
    }

    init {
        acceptor = Thread({ accept() }, "proxy-handshake").apply { isDaemon = true }
        reactor = Thread({ relay() }, "proxy-streams").apply { isDaemon = true }
        acceptor.start(); reactor.start()
    }

    private fun accept() {
        while (running) {
            val client = try { server.accept() } catch (_: Exception) { break }
            val owned = runCatching {
                ownerCheck(client.remoteAddress as InetSocketAddress, client.localAddress as InetSocketAddress)
            }.getOrDefault(false)
            if (!owned) { rejectedLocalClients.incrementAndGet(); runCatching { client.close() }; continue }
            if (slots.incrementAndGet() > 128) { slots.decrementAndGet(); client.close(); continue }
            channels.add(client)
            try { handshake.execute { negotiate(client) } }
            catch (_: Exception) { channels.remove(client); client.close(); slots.decrementAndGet() }
        }
    }

    private fun negotiate(client: SocketChannel) {
        var transferred = false
        try {
            client.socket().soTimeout = 15_000
            val input = DataInputStream(client.socket().getInputStream())
            val output = DataOutputStream(client.socket().getOutputStream())
            val version = input.readUnsignedByte()
            if (version == 'C'.code) { transferred = negotiateHttp(client, input, output); return }
            require(version == 5)
            val methods = ByteArray(input.readUnsignedByte()).also(input::readFully)
            if (2.toByte() !in methods) { output.write(byteArrayOf(5, -1)); return }
            output.write(byteArrayOf(5, 2)); output.flush()
            require(input.readUnsignedByte() == 1)
            val user = ByteArray(input.readUnsignedByte()).also(input::readFully)
            val secret = ByteArray(input.readUnsignedByte()).also(input::readFully)
            val authenticated = MessageDigest.isEqual(user, username.toByteArray()) && MessageDigest.isEqual(secret, password.toByteArray())
            output.write(byteArrayOf(1, if (authenticated) 0 else 1)); output.flush()
            if (!authenticated) return
            require(input.readUnsignedByte() == 5)
            val command = input.readUnsignedByte()
            require(input.readUnsignedByte() == 0)
            val target = readAddress(input)
            val targetPort = input.readUnsignedShort()
            if (command == 3) {
                reply(output, 0, udpPort)
                client.socket().soTimeout = 0
                client.configureBlocking(false)
                registrations.add(UdpControl(client, targetPort))
                transferred = true; selector.wakeup()
                return
            }
            if (command != 1 || targetPort == 0) { reply(output, 7); return }
            if (targetPort == 53) {
                reply(output, 0)
                client.socket().soTimeout = 0
                client.configureBlocking(false)
                registrations.add(DnsConnection(client))
                transferred = true; selector.wakeup()
                return
            }
            // Proxy CONNECT can wait for an unreachable IPv6/site destination.
            // Keep those waits away from local authentication and DNS setup.
            upstreamHandshake.execute { connectUpstream(client, target, targetPort) }
            transferred = true
        } catch (_: Exception) {
            runCatching { reply(DataOutputStream(client.socket().getOutputStream()), 1) }
        } finally {
            if (!transferred) {
                channels.remove(client); runCatching { client.close() }; slots.decrementAndGet()
            }
        }
    }

    /** HTTP CONNECT for DoH and OpenVPN. Credentials are required on the
     * first request; a missing or wrong value is answered with 407. */
    private fun negotiateHttp(client: SocketChannel, input: DataInputStream, output: DataOutputStream): Boolean {
        val header = java.io.ByteArrayOutputStream().apply { write('C'.code) }
        var tail = 'C'.code
        while (tail != 0x0D0A0D0A) {
            require(header.size() < 8192) { "Oversized CONNECT request" }
            val value = input.readUnsignedByte()
            header.write(value); tail = (tail shl 8) or value
        }
        val lines = header.toString(Charsets.US_ASCII).split("\r\n")
        val authority = Regex("CONNECT (\\S+) HTTP/1\\.[01]").matchEntire(lines.first())?.groupValues?.get(1)
        val credentials = lines.drop(1).firstOrNull { it.startsWith("Proxy-Authorization:", ignoreCase = true) }?.substringAfter(':')?.trim()
        if (credentials == null || !MessageDigest.isEqual(credentials.toByteArray(), basicAuthorization.toByteArray())) {
            output.write("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"relay\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .toByteArray(Charsets.US_ASCII))
            return false
        }
        val endpoint = authority?.let { runCatching { Endpoint.parse(it) }.getOrNull() }
        val host = endpoint?.host?.takeIf { it.none { character -> character.code < 33 || character in "[]/\\" } && it.length in 1..253 }
        if (endpoint == null || host == null) {
            output.write("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".toByteArray(Charsets.US_ASCII))
            return false
        }
        val target = if (host.contains(':')) InetAddress.getByName(host).hostAddress!! else IDN.toASCII(host, IDN.USE_STD3_ASCII_RULES)
        upstreamHandshake.execute { connectUpstream(client, target, endpoint.port, http = true) }
        return true
    }

    private fun connectUpstream(client: SocketChannel, target: String, targetPort: Int, http: Boolean = false) {
        var remote: SocketChannel? = null
        var transferred = false
        try {
            check(running)
            remote = SocketChannel.open()
            channels.add(remote)
            remote.socket().connect(InetSocketAddress(upstream.host, upstream.port), 15_000)
            remote.socket().soTimeout = 15_000
            when (kind) {
                ProxyKind.HTTP_CONNECT -> httpConnect(remote, target, targetPort)
                ProxyKind.SOCKS5 -> socksConnect(remote, target, targetPort)
            }
            if (http) client.socket().getOutputStream().write("HTTP/1.1 200 Connection established\r\n\r\n".toByteArray(Charsets.US_ASCII))
            else reply(DataOutputStream(client.socket().getOutputStream()), 0)
            client.socket().soTimeout = 0; remote.socket().soTimeout = 0
            client.configureBlocking(false); remote.configureBlocking(false)
            registrations.add(Session(client, remote)); transferred = true; selector.wakeup()
        } catch (_: Exception) {
            runCatching {
                if (http) client.socket().getOutputStream().write("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".toByteArray(Charsets.US_ASCII))
                else reply(DataOutputStream(client.socket().getOutputStream()), 1)
            }
        } finally {
            if (!transferred) {
                remote?.let { channels.remove(it); runCatching { it.close() } }
                channels.remove(client); runCatching { client.close() }; slots.decrementAndGet()
            }
        }
    }

    private fun relay() {
        while (running) {
            try {
                while (true) {
                    when (val connection = registrations.poll() ?: break) {
                        is Session -> {
                            connection.left.register(selector, SelectionKey.OP_READ, Side(connection, true))
                            connection.right.register(selector, SelectionKey.OP_READ, Side(connection, false))
                        }
                        is UdpControl -> {
                            associations.add(connection)
                            connection.channel.register(selector, SelectionKey.OP_READ, connection)
                        }
                        is DnsConnection -> connection.channel.register(selector, SelectionKey.OP_READ, connection)
                    }
                }
                while (true) (completions.poll() ?: break).invoke()
                selector.select(1000)
                val keys = selector.selectedKeys().iterator()
                while (keys.hasNext()) {
                    val key = keys.next(); keys.remove()
                    if (!key.isValid) continue
                    if (key.attachment() === udp) { datagram(); continue }
                    val attachment = key.attachment()
                    if (attachment is UdpControl) {
                        // A UDP association's lifetime follows its TCP control
                        // connection without occupying a handshake worker.
                        runCatching { attachment.channel.read(ByteBuffer.allocate(32)) }
                        closeControl(attachment)
                        continue
                    }
                    if (attachment is DnsConnection) {
                        try {
                            if (key.isReadable) {
                                if (attachment.channel.read(attachment.input) < 0) { closeDns(attachment); continue }
                                attachment.lastActivity = System.nanoTime()
                                dnsRequest(attachment)
                            }
                            if (key.isValid && key.isWritable) {
                                attachment.output?.let { buffer ->
                                    attachment.channel.write(buffer)
                                    if (!buffer.hasRemaining()) {
                                        attachment.output = null
                                        attachment.lastActivity = System.nanoTime()
                                        key.interestOps(SelectionKey.OP_READ)
                                        dnsRequest(attachment)
                                    }
                                }
                            }
                        } catch (_: Exception) { closeDns(attachment) }
                        continue
                    }
                    val side = key.attachment() as Side
                    val session = side.session
                    if (session.closed) continue
                    try {
                        val socket = if (side.left) session.left else session.right
                        val read = if (side.left) session.leftToRight else session.rightToLeft
                        val write = if (side.left) session.rightToLeft else session.leftToRight
                        if (key.isReadable && read.hasRemaining()) {
                            val count = socket.read(read)
                            if (count < 0) { if (side.left) session.leftEof = true else session.rightEof = true }
                            else if (count > 0) { if (side.left) sent.addAndGet(count.toLong()) else received.addAndGet(count.toLong()) }
                        }
                        if (key.isWritable && write.position() > 0) { write.flip(); socket.write(write); write.compact() }
                        update(session)
                    } catch (_: Exception) { closeSession(session) }
                }
                val now = System.nanoTime()
                selector.keys().toList().mapNotNull { it.attachment() as? DnsConnection }.forEach {
                    if (now - it.lastActivity > TimeUnit.MINUTES.toNanos(2)) closeDns(it)
                }
            } catch (_: Exception) { if (running) close() }
        }
    }

    private fun closeControl(connection: UdpControl) {
        if (connection.closed) return
        connection.closed = true
        associations.remove(connection)
        channels.remove(connection.channel)
        runCatching { connection.channel.close() }
        slots.decrementAndGet()
    }

    private fun closeDns(connection: DnsConnection) {
        if (connection.closed) return
        connection.closed = true
        channels.remove(connection.channel)
        runCatching { connection.channel.close() }
        slots.decrementAndGet()
    }

    private fun dnsRequest(connection: DnsConnection) {
        if (connection.pending || connection.output != null || connection.input.position() < 2) return
        val length = connection.input.getShort(0).toInt() and 65535
        require(length >= 12)
        if (connection.input.position() < length + 2) return
        connection.input.flip()
        connection.input.short
        val packet = ByteArray(length).also(connection.input::get)
        connection.input.compact()
        connection.pending = true
        connection.channel.keyFor(selector).interestOps(0)
        sent.addAndGet(length.toLong()); dnsRequests.incrementAndGet()
        try {
            dnsExecutor.execute {
                val response = runCatching { dns(packet) }.getOrElse { dnsFailures.incrementAndGet(); TunneledDns.failure(packet) }
                dnsResponses.incrementAndGet()
                completions.add {
                    if (!connection.closed && running) {
                        if (response.size !in 12..65535) closeDns(connection)
                        else {
                            received.addAndGet(response.size.toLong())
                            connection.output = ByteBuffer.allocate(response.size + 2).apply { putShort(response.size.toShort()); put(response); flip() }
                            connection.pending = false
                            connection.channel.keyFor(selector)?.interestOps(SelectionKey.OP_WRITE)
                        }
                    }
                }
                selector.wakeup()
            }
        } catch (_: Exception) { closeDns(connection) }
    }

    private fun update(session: Session) {
        if (session.leftEof && session.leftToRight.position() == 0 && !session.rightShutdown) { session.right.shutdownOutput(); session.rightShutdown = true }
        if (session.rightEof && session.rightToLeft.position() == 0 && !session.leftShutdown) { session.left.shutdownOutput(); session.leftShutdown = true }
        if (session.leftEof && session.rightEof && session.leftToRight.position() == 0 && session.rightToLeft.position() == 0) { closeSession(session); return }
        session.left.keyFor(selector)?.interestOps((if (!session.leftEof && session.leftToRight.hasRemaining()) SelectionKey.OP_READ else 0) or
            (if (session.rightToLeft.position() > 0) SelectionKey.OP_WRITE else 0))
        session.right.keyFor(selector)?.interestOps((if (!session.rightEof && session.rightToLeft.hasRemaining()) SelectionKey.OP_READ else 0) or
            (if (session.leftToRight.position() > 0) SelectionKey.OP_WRITE else 0))
    }

    private fun closeSession(session: Session) {
        if (session.closed) return
        session.closed = true
        channels.remove(session.left); channels.remove(session.right)
        session.left.close(); session.right.close(); slots.decrementAndGet()
    }

    private fun datagram() {
        val packet = ByteBuffer.allocate(65535)
        val source = udp.receive(packet) as? InetSocketAddress ?: return
        if (!source.address.isLoopbackAddress) return
        val association = associations.firstOrNull { it.learnedPort == source.port }
            ?: associations.firstOrNull { it.learnedPort == 0 } ?: run { unassociatedUdp.incrementAndGet(); return }
        association.learnedPort = source.port
        packet.flip()
        val wire = ByteArray(packet.remaining()).also(packet::get)
        try {
            val input = DataInputStream(wire.inputStream())
            require(input.readUnsignedShort() == 0 && input.readUnsignedByte() == 0)
            readAddress(input)
            if (input.readUnsignedShort() != 53) return
            val headerSize = wire.size - input.available()
            val query = input.readBytes()
            if (query.size !in 12..65535) return
            dnsRequests.incrementAndGet()
            dnsExecutor.execute {
                sent.addAndGet(query.size.toLong())
                val answer = runCatching {
                    val question = org.xbill.DNS.Message(query)
                    val limit = (question.opt?.payloadSize ?: 512).coerceIn(512, 1232)
                    org.xbill.DNS.Message(dns(query)).toWire(limit)
                }.getOrElse { dnsFailures.incrementAndGet(); TunneledDns.failure(query) }
                dnsResponses.incrementAndGet()
                if (answer.isNotEmpty()) completions.add {
                    if (running && !association.closed) {
                        udp.send(ByteBuffer.wrap(wire.copyOfRange(0, headerSize) + answer), source)
                        received.addAndGet(answer.size.toLong())
                    }
                }
                selector.wakeup()
            }
        } catch (_: Exception) { }
    }

    override fun close() {
        if (!running) return
        running = false
        runCatching { server.close() }; selector.wakeup()
        handshake.shutdownNow(); upstreamHandshake.shutdownNow(); dnsExecutor.shutdownNow()
        channels.forEach { runCatching { it.close() } }; channels.clear()
        runCatching { udp.close() }
        if (Thread.currentThread() !== reactor) reactor.join(2000)
        runCatching { selector.close() }
        if (Thread.currentThread() !== acceptor) acceptor.join(2000)
    }

    companion object {
        fun readAddress(input: DataInputStream): String = when (input.readUnsignedByte()) {
            1 -> InetAddress.getByAddress(ByteArray(4).also(input::readFully)).hostAddress!!
            4 -> InetAddress.getByAddress(ByteArray(16).also(input::readFully)).hostAddress!!
            3 -> {
                val bytes = ByteArray(input.readUnsignedByte()).also(input::readFully)
                val host = bytes.toString(Charsets.UTF_8)
                require(host.none { it.code < 33 || it in "[]:/\\" } && host.length in 1..253)
                IDN.toASCII(host, IDN.USE_STD3_ASCII_RULES)
            }
            else -> throw IllegalArgumentException("Invalid SOCKS address")
        }
        private fun reply(output: DataOutputStream, status: Int, port: Int = 0) {
            output.write(byteArrayOf(5, status.toByte(), 0, 1, 127, 0, 0, 1)); output.writeShort(port); output.flush()
        }
        private fun address(host: String, port: Int): ByteArray {
            val output = java.io.ByteArrayOutputStream()
            if (host.contains(':')) { output.write(4); output.write(InetAddress.getByName(host).address) }
            else { val bytes = host.toByteArray(Charsets.US_ASCII); require(bytes.size <= 255); output.write(3); output.write(bytes.size); output.write(bytes) }
            DataOutputStream(output).writeShort(port)
            return output.toByteArray()
        }
        private fun socksConnect(socket: SocketChannel, host: String, port: Int) {
            val output = DataOutputStream(socket.socket().getOutputStream())
            val input = DataInputStream(socket.socket().getInputStream())
            output.write(byteArrayOf(5, 1, 0)); output.flush()
            require(input.readUnsignedByte() == 5 && input.readUnsignedByte() == 0)
            output.write(byteArrayOf(5, 1, 0)); output.write(address(host, port)); output.flush()
            require(input.readUnsignedByte() == 5 && input.readUnsignedByte() == 0 && input.readUnsignedByte() == 0)
            readAddress(input); input.readUnsignedShort()
        }
        private fun httpConnect(socket: SocketChannel, host: String, port: Int) {
            val authority = if (host.contains(':')) "[$host]:$port" else "$host:$port"
            val output = socket.socket().getOutputStream()
            output.write("CONNECT $authority HTTP/1.1\r\nHost: $authority\r\n\r\n".toByteArray(Charsets.US_ASCII)); output.flush()
            val input = socket.socket().getInputStream()
            val header = java.io.ByteArrayOutputStream()
            var tail = 0
            while (header.size() < 32768) {
                val value = input.read(); require(value >= 0) { "Proxy closed before its response" }
                header.write(value); tail = (tail shl 8) or value
                if (tail == 0x0D0A0D0A) break
            }
            require(tail == 0x0D0A0D0A)
            val line = header.toString(Charsets.US_ASCII).substringBefore("\r\n")
            require(Regex("HTTP/1\\.[01] 2\\d\\d(?: .*)?").matches(line)) { "HTTP CONNECT was refused" }
        }
    }
}
