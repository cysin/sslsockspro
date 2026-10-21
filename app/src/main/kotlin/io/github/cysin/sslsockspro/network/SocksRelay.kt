package io.github.cysin.sslsockspro.network

import io.github.cysin.sslsockspro.config.Endpoint
import io.github.cysin.sslsockspro.model.ProxyKind
import java.io.DataInputStream
import java.net.IDN
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.StandardSocketOptions
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.ServerSocketChannel
import java.nio.channels.SocketChannel
import java.security.MessageDigest
import java.util.ArrayDeque
import java.util.Base64
import java.util.UUID
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/** Answers a DNS query asynchronously; [reply] may run on any thread. */
fun interface DnsHandler {
    fun resolve(query: ByteArray, reply: (ByteArray) -> Unit)
}

/** Authenticated local SOCKS5 and HTTP CONNECT frontend; the only client of
 * the stunnel listener in VPN modes. One non-blocking reactor performs local
 * handshakes, upstream proxy handshakes and transfers, so slow destinations
 * never hold a thread. Its UDP socket accepts DNS only and never forwards UDP.
 *
 * [ownerCheck] receives (peer, local) and admits only this app's sockets.
 * [target] maps a requested address to the name sent upstream (synthetic DNS
 * answers) and throws for an address that cannot be served. [keepWarm] says
 * whether pre-established upstream connections are worth their cost now.
 */
class SocksRelay(
    private val upstream: Endpoint,
    private val kind: ProxyKind,
    private val ownerCheck: (InetSocketAddress, InetSocketAddress) -> Boolean = { _, _ -> true },
    private val upstreamCredentials: Pair<String, String>? = null,
    private val target: (String) -> String = { it },
    private val keepWarm: () -> Boolean = { false },
    private val maxSessions: Int = 1024,
    private val dns: DnsHandler,
) : AutoCloseable {
    val username = "vpn"
    val password = UUID.randomUUID().toString().replace("-", "")
    private val selector = Selector.open()
    private val server = ServerSocketChannel.open().apply { bind(InetSocketAddress("127.0.0.1", 0)) }
    val port = (server.localAddress as InetSocketAddress).port
    private val udp = DatagramChannel.open().apply { bind(InetSocketAddress("127.0.0.1", 0)); configureBlocking(false) }
    private val udpPort = (udp.localAddress as InetSocketAddress).port
    private val upstreamAddress = InetSocketAddress(upstream.host, upstream.port)
    private val basicAuthorization = "Basic " + Base64.getEncoder().encodeToString("$username:$password".toByteArray())
    private val slots = AtomicInteger()
    private val accepted = ConcurrentLinkedQueue<SocketChannel>()
    private val completions = ConcurrentLinkedQueue<() -> Unit>()
    private val sessions = LinkedHashSet<Session>()
    private val associations = ArrayList<Session>()
    private val warm = ArrayDeque<Warm>()
    private val buffers = ArrayDeque<ByteBuffer>()
    private val datagram = ByteBuffer.allocateDirect(65535)
    private val dnsInFlight = AtomicInteger()
    private val acceptor: Thread
    private val reactor: Thread
    @Volatile private var running = true
    private var lastUpstreamUse = 0L
    val sent = AtomicLong()
    val received = AtomicLong()
    /** nanoTime of the last successful upstream handshake; a passive health signal. */
    val lastUpstreamSuccess = AtomicLong()
    private val dnsRequests = AtomicLong()
    private val dnsResponses = AtomicLong()
    private val dnsFailures = AtomicLong()
    private val unassociatedUdp = AtomicLong()
    private val rejectedLocalClients = AtomicLong()
    private val evicted = AtomicLong()
    private val warmUsed = AtomicLong()

    fun diagnostics(): String = "DNS requests=${dnsRequests.get()} replies=${dnsResponses.get()} failures=${dnsFailures.get()} in flight=${dnsInFlight.get()}; " +
        "unassociated UDP=${unassociatedUdp.get()}; rejected local clients=${rejectedLocalClients.get()}; connections=${slots.get()}; " +
        "evicted idle=${evicted.get()}; warm connections used=${warmUsed.get()}"

    private enum class Stage { GREETING, CREDENTIALS, REQUEST, HTTP_REQUEST, CONNECTING, UPSTREAM, STREAM, DNS, UDP_CONTROL }
    private enum class Answer { METHOD, AUTH, REPLY }

    private inner class Session(val left: SocketChannel) {
        var stage = Stage.GREETING
        var right: SocketChannel? = null
        val inbound: ByteBuffer = buffer()
        var outbound: ByteBuffer? = null
        val replies = ArrayDeque<ByteBuffer>()
        var request: ByteBuffer? = null
        var http = false
        var targetHost = ""
        var targetPort = 0
        var answer = Answer.METHOD
        var usedWarm = false
        var responded = false
        var leftEof = false; var rightEof = false
        var leftShutdown = false; var rightShutdown = false
        var closeAfterReplies = false
        var closed = false
        var deadline = System.nanoTime() + HANDSHAKE
        var lastActivity = System.nanoTime()
        var dnsPending = false
        var dnsOutput: ByteBuffer? = null
        var learnedPort = 0
    }
    private data class Side(val session: Any, val left: Boolean)
    private class Warm(val channel: SocketChannel, val created: Long) { var connected = false }

    init {
        server.configureBlocking(true)
        udp.register(selector, SelectionKey.OP_READ, udp)
        acceptor = Thread({ accept() }, "proxy-admission").apply { isDaemon = true }
        reactor = Thread({ relay() }, "proxy-streams").apply { isDaemon = true }
        acceptor.start(); reactor.start()
    }

    private fun buffer(): ByteBuffer = buffers.pollFirst()?.also { it.clear() } ?: ByteBuffer.allocateDirect(BUFFER)
    private fun recycle(buffer: ByteBuffer?) { if (buffer != null && buffers.size < POOLED_BUFFERS) buffers.addLast(buffer) }

    /** Admission runs off the reactor: owner lookups are Binder calls. */
    private fun accept() {
        while (running) {
            val client = try { server.accept() } catch (_: Exception) { break }
            val owned = runCatching {
                ownerCheck(client.remoteAddress as InetSocketAddress, client.localAddress as InetSocketAddress)
            }.getOrDefault(false)
            if (!owned) { rejectedLocalClients.incrementAndGet(); runCatching { client.close() }; continue }
            accepted.add(client); selector.wakeup()
        }
    }

    private fun relay() {
        var nextTimer = System.nanoTime()
        while (running) {
            try {
                while (true) admit(accepted.poll() ?: break)
                while (true) (completions.poll() ?: break).invoke()
                selector.select(1000)
                val keys = selector.selectedKeys().iterator()
                while (keys.hasNext()) {
                    val key = keys.next(); keys.remove()
                    if (!key.isValid) continue
                    when (val attachment = key.attachment()) {
                        udp -> receiveDatagram()
                        is Warm -> warmReady(key, attachment)
                        is Side -> handle(key, attachment.session as Session, attachment.left)
                    }
                }
                val now = System.nanoTime()
                if (now >= nextTimer) { timers(now); nextTimer = now + TimeUnit.SECONDS.toNanos(1) }
            } catch (_: Exception) { if (running) close() }
        }
    }

    private fun admit(client: SocketChannel) {
        if (slots.get() >= maxSessions * 9 / 10) evictIdle()
        if (slots.get() >= maxSessions) { runCatching { client.close() }; return }
        slots.incrementAndGet()
        client.configureBlocking(false)
        client.setOption(StandardSocketOptions.TCP_NODELAY, true)
        val session = Session(client)
        sessions += session
        client.register(selector, SelectionKey.OP_READ, Side(session, true))
    }

    /** Near the limit, idle streams yield to new connections, oldest first. */
    private fun evictIdle() {
        val threshold = System.nanoTime() - IDLE_EVICTION
        val candidates = sessions.filter { it.stage == Stage.STREAM && it.lastActivity < threshold }.sortedBy { it.lastActivity }
        for (session in candidates) {
            if (slots.get() < maxSessions * 9 / 10) break
            evicted.incrementAndGet(); closeSession(session)
        }
    }

    private fun handle(key: SelectionKey, session: Session, left: Boolean) {
        if (session.closed) return
        try {
            session.lastActivity = System.nanoTime()
            if (left) {
                if (key.isReadable) readLeft(session)
                if (key.isValid && key.isWritable && !session.closed) writeLeft(session)
            } else {
                if (key.isConnectable) finishConnect(session)
                if (key.isValid && key.isReadable && !session.closed) readRight(session)
                if (key.isValid && key.isWritable && !session.closed) writeRight(session)
            }
            if (!session.closed) update(session)
        } catch (_: Exception) { fail(session) }
    }

    private fun readLeft(session: Session) {
        if (session.stage == Stage.UDP_CONTROL) {
            // A UDP association lives as long as its TCP control connection.
            closeSession(session); return
        }
        val buffer = session.inbound
        if (!buffer.hasRemaining() || session.leftEof) return
        val count = session.left.read(buffer)
        if (count < 0) {
            session.leftEof = true
            if (session.stage !in setOf(Stage.STREAM, Stage.UPSTREAM, Stage.CONNECTING)) closeSession(session)
            return
        }
        if (count > 0 && session.stage == Stage.STREAM) sent.addAndGet(count.toLong())
        when (session.stage) {
            Stage.GREETING, Stage.CREDENTIALS, Stage.REQUEST, Stage.HTTP_REQUEST -> negotiate(session)
            Stage.DNS -> dnsRequest(session)
            else -> Unit
        }
    }

    private fun writeLeft(session: Session) {
        while (session.replies.isNotEmpty()) {
            val reply = session.replies.peekFirst()
            session.left.write(reply)
            if (reply.hasRemaining()) return
            session.replies.removeFirst()
        }
        if (session.closeAfterReplies) { closeSession(session); return }
        if (session.stage == Stage.DNS) {
            session.dnsOutput?.let { output ->
                session.left.write(output)
                if (!output.hasRemaining()) { session.dnsOutput = null; dnsRequest(session) }
            }
            return
        }
        val outbound = session.outbound
        if (session.stage == Stage.STREAM && outbound != null && outbound.position() > 0) {
            outbound.flip(); session.left.write(outbound); outbound.compact()
        }
    }

    private fun readRight(session: Session) {
        val right = session.right ?: return
        val buffer = session.outbound ?: return
        if (!buffer.hasRemaining() || session.rightEof) return
        val count = right.read(buffer)
        if (count < 0) {
            session.rightEof = true
            if (session.stage == Stage.UPSTREAM) upstreamFailed(session)
            return
        }
        if (count == 0) return
        session.responded = true
        if (session.stage == Stage.STREAM) received.addAndGet(count.toLong())
        else if (session.stage == Stage.UPSTREAM) parseUpstream(session)
    }

    private fun writeRight(session: Session) {
        val right = session.right ?: return
        if (session.stage == Stage.CONNECTING) return
        session.request?.let { request ->
            right.write(request)
            if (request.hasRemaining()) return
            session.request = null
        }
        if (session.stage == Stage.STREAM && session.inbound.position() > 0) {
            session.inbound.flip(); right.write(session.inbound); session.inbound.compact()
        }
    }

    // Local handshakes: SOCKS5 with username/password, or HTTP CONNECT with
    // Basic credentials. Pipelined input is parsed in order.

    private fun negotiate(session: Session) {
        while (!session.closed && !session.closeAfterReplies) {
            val view = session.inbound.duplicate().also { it.flip() }
            val consumed = when (session.stage) {
                Stage.GREETING -> greeting(session, view)
                Stage.CREDENTIALS -> credentials(session, view)
                Stage.REQUEST -> request(session, view)
                Stage.HTTP_REQUEST -> httpRequest(session, view)
                else -> return
            } ?: return
            if (session.closed) return
            session.inbound.flip(); session.inbound.position(consumed); session.inbound.compact()
            if (session.stage == Stage.DNS) { dnsRequest(session); return }
            if (session.stage !in setOf(Stage.GREETING, Stage.CREDENTIALS, Stage.REQUEST, Stage.HTTP_REQUEST)) return
        }
    }

    private fun reply(session: Session, bytes: ByteArray) { session.replies.addLast(ByteBuffer.wrap(bytes)) }
    private fun refuse(session: Session, bytes: ByteArray) { reply(session, bytes); session.closeAfterReplies = true }

    private fun greeting(session: Session, view: ByteBuffer): Int? {
        if (view.remaining() < 1) return null
        val version = view.get(0).toInt() and 255
        if (version == 'C'.code) { session.http = true; session.stage = Stage.HTTP_REQUEST; return 0 }
        if (version != 5) { closeSession(session); return null }
        if (view.remaining() < 2) return null
        val count = view.get(1).toInt() and 255
        if (view.remaining() < 2 + count) return null
        val methods = (0 until count).map { view.get(2 + it).toInt() and 255 }
        if (2 !in methods) { refuse(session, byteArrayOf(5, -1)); return 2 + count }
        reply(session, byteArrayOf(5, 2))
        session.stage = Stage.CREDENTIALS
        return 2 + count
    }

    private fun credentials(session: Session, view: ByteBuffer): Int? {
        if (view.remaining() < 2) return null
        val userLength = view.get(1).toInt() and 255
        if (view.remaining() < 3 + userLength) return null
        val secretLength = view.get(2 + userLength).toInt() and 255
        val total = 3 + userLength + secretLength
        if (view.remaining() < total) return null
        val user = ByteArray(userLength).also { view.position(2); view.get(it) }
        val secret = ByteArray(secretLength).also { view.position(3 + userLength); view.get(it) }
        val authenticated = view.get(0).toInt() == 1 &&
            MessageDigest.isEqual(user, username.toByteArray()) && MessageDigest.isEqual(secret, password.toByteArray())
        if (!authenticated) { refuse(session, byteArrayOf(1, 1)); return total }
        reply(session, byteArrayOf(1, 0))
        session.stage = Stage.REQUEST
        return total
    }

    private fun request(session: Session, view: ByteBuffer): Int? {
        if (view.remaining() < 5) return null
        val command = view.get(1).toInt() and 255
        val addressLength = when (view.get(3).toInt()) {
            1 -> 4; 4 -> 16
            3 -> 1 + (view.get(4).toInt() and 255)
            else -> { refuse(session, socksReply(8)); return view.remaining() }
        }
        val total = 4 + addressLength + 2
        if (view.remaining() < total) return null
        val input = DataInputStream(ByteArray(total).also { view.get(it) }.inputStream())
        input.skipBytes(3)
        val address = runCatching { readAddress(input) }.getOrNull()
        val port = if (address == null) 0 else input.readUnsignedShort()
        when {
            address == null -> refuse(session, socksReply(1))
            command == 3 -> {
                reply(session, socksReply(0, udpPort))
                session.learnedPort = port
                session.stage = Stage.UDP_CONTROL
                associations += session
            }
            command != 1 || port == 0 -> refuse(session, socksReply(7))
            port == 53 -> { reply(session, socksReply(0)); session.stage = Stage.DNS; session.lastActivity = System.nanoTime() }
            else -> connect(session, address, port)
        }
        return total
    }

    private fun httpRequest(session: Session, view: ByteBuffer): Int? {
        val bytes = ByteArray(view.remaining()).also { view.get(it) }
        val end = bytes.indexOfSequence(HEADER_END)
        if (end < 0) {
            if (bytes.size < 8192) return null
            refuse(session, httpStatus("400 Bad Request")); return bytes.size
        }
        val lines = String(bytes, 0, end, Charsets.US_ASCII).split("\r\n")
        val authority = Regex("CONNECT (\\S+) HTTP/1\\.[01]").matchEntire(lines.first())?.groupValues?.get(1)
        val credentials = lines.drop(1).firstOrNull { it.startsWith("Proxy-Authorization:", ignoreCase = true) }?.substringAfter(':')?.trim()
        val consumed = end + HEADER_END.size
        if (credentials == null || !MessageDigest.isEqual(credentials.toByteArray(), basicAuthorization.toByteArray())) {
            refuse(session, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"relay\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .toByteArray(Charsets.US_ASCII))
            return consumed
        }
        val endpoint = authority?.let { runCatching { Endpoint.parse(it) }.getOrNull() }
        val host = endpoint?.host?.takeIf { it.none { character -> character.code < 33 || character in "[]/\\" } && it.length in 1..253 }
        val address = host?.let { runCatching { if (it.contains(':')) InetAddress.getByName(it).hostAddress!! else IDN.toASCII(it, IDN.USE_STD3_ASCII_RULES) }.getOrNull() }
        if (endpoint == null || address == null) { refuse(session, httpStatus("400 Bad Request")); return consumed }
        connect(session, address, endpoint.port)
        return consumed
    }

    // Upstream: one pipelined request through stunnel to the HTTP or SOCKS5
    // backend. Bytes the destination sends after the handshake are kept.

    private fun connect(session: Session, address: String, port: Int) {
        val name = try { target(address) } catch (_: Exception) {
            refuse(session, if (session.http) httpStatus("502 Bad Gateway") else socksReply(4)); return
        }
        session.targetHost = name; session.targetPort = port
        session.deadline = System.nanoTime() + HANDSHAKE
        session.outbound = buffer()
        lastUpstreamUse = System.nanoTime()
        val reused = takeWarm()
        if (reused != null) {
            warmUsed.incrementAndGet()
            session.usedWarm = true
            session.right = reused.channel
            // Reuse the registration; re-registering would need a select.
            reused.key.attach(Side(session, false))
            beginUpstream(session)
        } else openUpstream(session)
    }

    private fun openUpstream(session: Session) {
        val channel = SocketChannel.open()
        session.right = channel
        channel.configureBlocking(false)
        channel.setOption(StandardSocketOptions.TCP_NODELAY, true)
        session.stage = Stage.CONNECTING
        if (channel.connect(upstreamAddress)) {
            channel.register(selector, SelectionKey.OP_WRITE or SelectionKey.OP_READ, Side(session, false))
            beginUpstream(session)
        } else channel.register(selector, SelectionKey.OP_CONNECT, Side(session, false))
    }

    private fun finishConnect(session: Session) {
        if (session.stage != Stage.CONNECTING) return
        if (!session.right!!.finishConnect()) return
        beginUpstream(session)
    }

    private fun beginUpstream(session: Session) {
        session.stage = Stage.UPSTREAM
        session.answer = Answer.METHOD
        session.request = ByteBuffer.wrap(upstreamRequest(session.targetHost, session.targetPort))
    }

    private fun upstreamRequest(host: String, port: Int): ByteArray {
        val output = java.io.ByteArrayOutputStream()
        val credentials = upstreamCredentials
        when (kind) {
            ProxyKind.HTTP_CONNECT -> {
                val authority = if (host.contains(':')) "[$host]:$port" else "$host:$port"
                val authorization = credentials?.let {
                    "Proxy-Authorization: Basic " + Base64.getEncoder().encodeToString("${it.first}:${it.second}".toByteArray()) + "\r\n"
                }.orEmpty()
                output.write("CONNECT $authority HTTP/1.1\r\nHost: $authority\r\n$authorization\r\n".toByteArray(Charsets.US_ASCII))
            }
            ProxyKind.SOCKS5 -> {
                // Greeting, credentials and request in one write: one round
                // trip instead of two (or three with authentication).
                output.write(byteArrayOf(5, 1, if (credentials != null) 2 else 0))
                if (credentials != null) {
                    val user = credentials.first.toByteArray(); val secret = credentials.second.toByteArray()
                    output.write(1); output.write(user.size); output.write(user); output.write(secret.size); output.write(secret)
                }
                output.write(byteArrayOf(5, 1, 0)); output.write(address(host, port))
            }
        }
        return output.toByteArray()
    }

    private fun parseUpstream(session: Session) {
        val buffer = session.outbound!!
        val view = buffer.duplicate().also { it.flip() }
        val consumed = when (kind) {
            ProxyKind.HTTP_CONNECT -> {
                val bytes = ByteArray(view.remaining()).also { view.get(it) }
                val end = bytes.indexOfSequence(HEADER_END)
                if (end < 0) { if (!buffer.hasRemaining()) upstreamFailed(session, refusedByProxy = true); return }
                val status = String(bytes, 0, end, Charsets.US_ASCII).substringBefore("\r\n")
                if (!Regex("HTTP/1\\.[01] 2\\d\\d(?: .*)?").matches(status)) { upstreamFailed(session, refusedByProxy = true); return }
                end + HEADER_END.size
            }
            ProxyKind.SOCKS5 -> socksAnswer(session, view) ?: return
        }
        buffer.flip(); buffer.position(consumed); buffer.compact()
        if (session.stage != Stage.UPSTREAM) return
        session.stage = Stage.STREAM
        session.deadline = Long.MAX_VALUE
        lastUpstreamSuccess.set(System.nanoTime())
        reply(session, if (session.http) "HTTP/1.1 200 Connection established\r\n\r\n".toByteArray(Charsets.US_ASCII) else socksReply(0))
        // Destination bytes that arrived with the handshake, and client bytes
        // sent before it completed, are counted as data now.
        received.addAndGet(buffer.position().toLong())
        sent.addAndGet(session.inbound.position().toLong())
    }

    /** Parses pipelined SOCKS5 answers; returns bytes consumed once the
     * request reply is complete, or null while more data is needed. */
    private fun socksAnswer(session: Session, view: ByteBuffer): Int? {
        var offset = 0
        while (true) {
            val available = view.remaining() - offset
            when (session.answer) {
                Answer.METHOD -> {
                    if (available < 2) return null
                    val method = view.get(offset + 1).toInt() and 255
                    val expected = if (upstreamCredentials != null) 2 else 0
                    if (view.get(offset).toInt() != 5 || method != expected) { upstreamFailed(session, refusedByProxy = true); return null }
                    offset += 2
                    session.answer = if (expected == 2) Answer.AUTH else Answer.REPLY
                }
                Answer.AUTH -> {
                    if (available < 2) return consumedSoFar(session, offset)
                    if (view.get(offset + 1).toInt() != 0) { upstreamFailed(session, refusedByProxy = true); return null }
                    offset += 2
                    session.answer = Answer.REPLY
                }
                Answer.REPLY -> {
                    if (available < 5) return consumedSoFar(session, offset)
                    if (view.get(offset).toInt() != 5 || view.get(offset + 1).toInt() != 0) { upstreamFailed(session, refusedByProxy = true); return null }
                    val length = when (view.get(offset + 3).toInt()) {
                        1 -> 4; 4 -> 16; 3 -> 1 + (view.get(offset + 4).toInt() and 255)
                        else -> { upstreamFailed(session, refusedByProxy = true); return null }
                    }
                    if (available < 4 + length + 2) return consumedSoFar(session, offset)
                    return offset + 4 + length + 2
                }
            }
        }
    }

    /** Keeps parsed answer prefixes out of the buffer while more is awaited. */
    private fun consumedSoFar(session: Session, offset: Int): Int? {
        if (offset > 0) { val buffer = session.outbound!!; buffer.flip(); buffer.position(offset); buffer.compact() }
        return null
    }

    private fun upstreamFailed(session: Session, refusedByProxy: Boolean = false) {
        if (session.closed || session.stage == Stage.STREAM) return
        // A warm connection may have been closed by the server while idle.
        // Nothing reached the destination, so retry once on a new one.
        if (session.usedWarm && !refusedByProxy && !session.responded) {
            session.usedWarm = false
            session.right?.let { runCatching { it.close() } }
            session.outbound?.clear()
            session.rightEof = false
            openUpstream(session)
            return
        }
        session.right?.let { runCatching { it.close() } }
        session.right = null
        session.request = null
        session.stage = Stage.REQUEST
        refuse(session, if (session.http) httpStatus("502 Bad Gateway") else socksReply(1))
    }

    private fun fail(session: Session) {
        if (session.closed) return
        if (session.stage == Stage.CONNECTING || session.stage == Stage.UPSTREAM) {
            runCatching { upstreamFailed(session); update(session) }.onFailure { closeSession(session) }
        } else closeSession(session)
    }

    private fun update(session: Session) {
        val leftKey = session.left.keyFor(selector) ?: return
        val right = session.right
        if (session.stage == Stage.STREAM) {
            val inbound = session.inbound
            val outbound = session.outbound!!
            if (session.leftEof && inbound.position() == 0 && !session.rightShutdown && session.request == null) { right!!.shutdownOutput(); session.rightShutdown = true }
            if (session.rightEof && outbound.position() == 0 && session.replies.isEmpty() && !session.leftShutdown) { session.left.shutdownOutput(); session.leftShutdown = true }
            if (session.leftEof && session.rightEof && inbound.position() == 0 && outbound.position() == 0 && session.replies.isEmpty()) { closeSession(session); return }
            leftKey.interestOps((if (!session.leftEof && inbound.hasRemaining()) SelectionKey.OP_READ else 0) or
                (if (outbound.position() > 0 || session.replies.isNotEmpty()) SelectionKey.OP_WRITE else 0))
            right!!.keyFor(selector)?.interestOps((if (!session.rightEof && outbound.hasRemaining()) SelectionKey.OP_READ else 0) or
                (if (inbound.position() > 0 || session.request != null) SelectionKey.OP_WRITE else 0))
            return
        }
        if (session.closeAfterReplies && session.replies.isEmpty()) { closeSession(session); return }
        val reading = when (session.stage) {
            Stage.DNS -> !session.dnsPending && session.dnsOutput == null
            Stage.CONNECTING, Stage.UPSTREAM -> !session.leftEof && session.inbound.hasRemaining()
            else -> !session.closeAfterReplies
        }
        val writing = session.replies.isNotEmpty() || session.dnsOutput != null
        leftKey.interestOps((if (reading) SelectionKey.OP_READ else 0) or (if (writing) SelectionKey.OP_WRITE else 0))
        if (session.stage == Stage.UPSTREAM) right?.keyFor(selector)?.interestOps(SelectionKey.OP_READ or (if (session.request != null) SelectionKey.OP_WRITE else 0))
    }

    private fun closeSession(session: Session) {
        if (session.closed) return
        session.closed = true
        sessions -= session
        associations -= session
        runCatching { session.left.close() }
        session.right?.let { runCatching { it.close() } }
        recycle(session.inbound); recycle(session.outbound)
        slots.decrementAndGet()
    }

    // Pre-established upstream connections. stunnel completes TCP and TLS
    // to the server as soon as it accepts, so a held connection saves those
    // round trips for the next request. Kept only while traffic is recent.

    private class Reused(val channel: SocketChannel, val key: SelectionKey)

    private fun takeWarm(): Reused? {
        while (true) {
            val entry = warm.firstOrNull { it.connected } ?: return null
            warm.remove(entry)
            val key = entry.channel.keyFor(selector)
            if (entry.channel.isOpen && key != null && key.isValid) return Reused(entry.channel, key)
            runCatching { entry.channel.close() }
        }
    }

    private fun warmReady(key: SelectionKey, entry: Warm) {
        try {
            if (key.isConnectable) { if (entry.channel.finishConnect()) { entry.connected = true; key.interestOps(SelectionKey.OP_READ) } }
            // Readable while idle means the server closed it.
            else if (key.isReadable) dropWarm(entry)
        } catch (_: Exception) { dropWarm(entry) }
    }

    private fun dropWarm(entry: Warm) { warm.remove(entry); runCatching { entry.channel.close() } }

    private fun maintainWarm(now: Long) {
        warm.filter { now - it.created > WARM_AGE }.forEach(::dropWarm)
        val wanted = if (lastUpstreamUse != 0L && now - lastUpstreamUse < WARM_WINDOW && runCatching(keepWarm).getOrDefault(false)) WARM_SIZE else 0
        while (warm.size > wanted) dropWarm(warm.first())
        while (warm.size < wanted) {
            val channel = SocketChannel.open()
            val entry = Warm(channel, now)
            try {
                channel.configureBlocking(false)
                channel.setOption(StandardSocketOptions.TCP_NODELAY, true)
                if (channel.connect(upstreamAddress)) { entry.connected = true; channel.register(selector, SelectionKey.OP_READ, entry) }
                else channel.register(selector, SelectionKey.OP_CONNECT, entry)
                warm.addLast(entry)
            } catch (_: Exception) { runCatching { channel.close() }; break }
        }
    }

    /** Connections on the previous physical network are useless. */
    fun networkChanged() {
        completions.add { warm.toList().forEach(::dropWarm) }
        selector.wakeup()
    }

    private fun timers(now: Long) {
        for (session in sessions.toList()) {
            if (session.closed) continue
            val handshaking = session.stage in setOf(Stage.GREETING, Stage.CREDENTIALS, Stage.REQUEST, Stage.HTTP_REQUEST, Stage.CONNECTING, Stage.UPSTREAM)
            if (handshaking && now > session.deadline) fail(session)
            else if (session.stage == Stage.DNS && !session.dnsPending && now - session.lastActivity > DNS_IDLE) closeSession(session)
        }
        maintainWarm(now)
    }

    // DNS: TCP queries on port 53 and UDP associations carry only DNS.

    private fun dnsRequest(session: Session) {
        val input = session.inbound
        if (session.dnsPending || session.dnsOutput != null || input.position() < 2) return
        val length = input.getShort(0).toInt() and 65535
        if (length < 12) { closeSession(session); return }
        if (input.position() < length + 2) return
        input.flip(); input.short
        val packet = ByteArray(length).also(input::get)
        input.compact()
        session.dnsPending = true
        sent.addAndGet(length.toLong())
        query(packet) { response ->
            if (session.closed || !running) return@query
            session.dnsPending = false
            session.lastActivity = System.nanoTime()
            if (response.size !in 12..65535) { closeSession(session); return@query }
            received.addAndGet(response.size.toLong())
            session.dnsOutput = ByteBuffer.allocate(response.size + 2).apply { putShort(response.size.toShort()); put(response); flip() }
            runCatching { update(session) }.onFailure { closeSession(session) }
        }
    }

    /** Bounded asynchronous resolution; [complete] runs on the reactor. */
    private fun query(packet: ByteArray, complete: (ByteArray) -> Unit) {
        dnsRequests.incrementAndGet()
        if (dnsInFlight.incrementAndGet() > MAX_DNS_IN_FLIGHT) {
            dnsInFlight.decrementAndGet(); dnsFailures.incrementAndGet()
            complete(TunneledDns.failure(packet)); return
        }
        val done = AtomicBoolean()
        fun finish(response: ByteArray) {
            if (!done.compareAndSet(false, true)) return
            dnsInFlight.decrementAndGet(); dnsResponses.incrementAndGet()
            completions.add { complete(response) }; selector.wakeup()
        }
        try { dns.resolve(packet) { finish(it) } }
        catch (_: Exception) { dnsFailures.incrementAndGet(); finish(TunneledDns.failure(packet)) }
    }

    private fun receiveDatagram() {
        datagram.clear()
        val source = udp.receive(datagram) as? InetSocketAddress ?: return
        if (!source.address.isLoopbackAddress) return
        val association = associations.firstOrNull { it.learnedPort == source.port }
            ?: associations.firstOrNull { it.learnedPort == 0 } ?: run { unassociatedUdp.incrementAndGet(); return }
        association.learnedPort = source.port
        datagram.flip()
        val wire = ByteArray(datagram.remaining()).also(datagram::get)
        try {
            val input = DataInputStream(wire.inputStream())
            require(input.readUnsignedShort() == 0 && input.readUnsignedByte() == 0)
            readAddress(input)
            if (input.readUnsignedShort() != 53) return
            val headerSize = wire.size - input.available()
            val question = input.readBytes()
            if (question.size !in 12..65535) return
            val limit = runCatching { (org.xbill.DNS.Message(question).opt?.payloadSize ?: 512).coerceIn(512, 1232) }.getOrDefault(512)
            sent.addAndGet(question.size.toLong())
            query(question) { response ->
                if (!running || association.closed) return@query
                val answer = runCatching { org.xbill.DNS.Message(response).toWire(limit) }.getOrDefault(response)
                if (answer.isEmpty()) return@query
                runCatching { udp.send(ByteBuffer.wrap(wire.copyOfRange(0, headerSize) + answer), source) }
                received.addAndGet(answer.size.toLong())
            }
        } catch (_: Exception) { }
    }

    override fun close() {
        if (!running) return
        running = false
        runCatching { server.close() }; selector.wakeup()
        if (Thread.currentThread() !== reactor) reactor.join(2000)
        sessions.toList().forEach(::closeSession)
        warm.toList().forEach(::dropWarm)
        accepted.forEach { runCatching { it.close() } }
        runCatching { udp.close() }
        runCatching { selector.close() }
        if (Thread.currentThread() !== acceptor) acceptor.join(2000)
    }

    companion object {
        private const val BUFFER = 16 * 1024
        private const val POOLED_BUFFERS = 256
        private const val MAX_DNS_IN_FLIGHT = 256
        private const val WARM_SIZE = 2
        private val HANDSHAKE = TimeUnit.SECONDS.toNanos(15)
        private val IDLE_EVICTION = TimeUnit.MINUTES.toNanos(5)
        private val DNS_IDLE = TimeUnit.MINUTES.toNanos(2)
        private val WARM_AGE = TimeUnit.SECONDS.toNanos(30)
        private val WARM_WINDOW = TimeUnit.SECONDS.toNanos(60)
        private val HEADER_END = "\r\n\r\n".toByteArray(Charsets.US_ASCII)

        private fun ByteArray.indexOfSequence(sequence: ByteArray): Int {
            outer@ for (start in 0..size - sequence.size) {
                for (index in sequence.indices) if (this[start + index] != sequence[index]) continue@outer
                return start
            }
            return -1
        }

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

        private fun socksReply(status: Int, port: Int = 0): ByteArray =
            byteArrayOf(5, status.toByte(), 0, 1, 127, 0, 0, 1, (port shr 8).toByte(), port.toByte())

        private fun httpStatus(status: String): ByteArray =
            "HTTP/1.1 $status\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".toByteArray(Charsets.US_ASCII)

        /** IPv4 and IPv6 literals use their own address types, never a name. */
        internal fun address(host: String, port: Int): ByteArray {
            val output = java.io.ByteArrayOutputStream()
            when {
                host.contains(':') -> { output.write(4); output.write(InetAddress.getByName(host).address) }
                Regex("(?:\\d{1,3}\\.){3}\\d{1,3}").matches(host) && host.split('.').all { it.toInt() <= 255 } -> {
                    output.write(1); host.split('.').forEach { output.write(it.toInt()) }
                }
                else -> { val bytes = host.toByteArray(Charsets.US_ASCII); require(bytes.size <= 255); output.write(3); output.write(bytes.size); output.write(bytes) }
            }
            output.write(port shr 8); output.write(port and 255)
            return output.toByteArray()
        }
    }
}
