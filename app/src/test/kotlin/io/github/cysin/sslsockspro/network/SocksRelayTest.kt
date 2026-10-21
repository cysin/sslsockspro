package io.github.cysin.sslsockspro.network

import io.github.cysin.sslsockspro.config.Endpoint
import io.github.cysin.sslsockspro.model.ProxyKind
import org.junit.Assert.*
import org.junit.Test
import org.xbill.DNS.Message
import org.xbill.DNS.Name
import org.xbill.DNS.Type
import org.xbill.DNS.DClass
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class SocksRelayTest {
    @Test(timeout = 15000) fun slowProxyHandshakesDoNotBlockDnsSetup() {
        ServerSocket(0, 10, InetAddress.getLoopbackAddress()).use { upstream ->
            val accepted = CountDownLatch(4)
            val peers = java.util.Collections.synchronizedList(mutableListOf<Socket>())
            val server = thread(isDaemon = true) {
                repeat(4) { peers.add(upstream.accept()); accepted.countDown() }
            }
            val clients = mutableListOf<Socket>()
            try {
                SocksRelay(Endpoint("127.0.0.1", upstream.localPort), ProxyKind.HTTP_CONNECT) {
                    query, reply -> reply(TunneledDns.response(Message(query), 0).toWire())
                }.use { relay ->
                    repeat(4) {
                        val client = authenticated(relay); clients += client
                        DataOutputStream(client.getOutputStream()).apply {
                            write(byteArrayOf(5, 1, 0, 3, 12)); writeBytes("example.test"); writeShort(443); flush()
                        }
                    }
                    assertTrue("Four proxy handshakes should be waiting", accepted.await(3, TimeUnit.SECONDS))
                    authenticated(relay).use { dns ->
                        request(dns, 1, "8.8.8.8", 53)
                        val query = Message.newQuery(org.xbill.DNS.Record.newRecord(Name.fromString("example.test."), Type.A, DClass.IN)).toWire()
                        DataOutputStream(dns.getOutputStream()).apply { writeShort(query.size); write(query); flush() }
                        val input = DataInputStream(dns.getInputStream())
                        val answer = ByteArray(input.readUnsignedShort()).also(input::readFully)
                        assertTrue(Message(answer).header.getFlag(org.xbill.DNS.Flags.QR.toInt()))
                    }
                }
            } finally { clients.forEach { it.close() }; peers.forEach { it.close() }; server.join(1000) }
        }
    }
    @Test(timeout = 15000) fun persistentUdpAndDnsConnectionsDoNotStarveHandshakes() {
        SocksRelay(Endpoint("127.0.0.1", 9), ProxyKind.HTTP_CONNECT) { query, reply -> reply(TunneledDns.response(Message(query), 0).toWire()) }.use { relay ->
            val controls = mutableListOf<Socket>()
            try {
                repeat(8) {
                    controls += authenticated(relay).also { request(it, 3, "0.0.0.0", 0) }
                }
                repeat(8) {
                    controls += authenticated(relay).also { request(it, 1, "8.8.8.8", 53) }
                }
                val packet = Message.newQuery(org.xbill.DNS.Record.newRecord(Name.fromString("example.test."), Type.A, DClass.IN)).toWire()
                controls.takeLast(8).forEach { socket ->
                    val output = DataOutputStream(socket.getOutputStream())
                    output.writeShort(packet.size); output.write(packet); output.flush()
                }
                controls.takeLast(8).forEach { socket ->
                    val input = DataInputStream(socket.getInputStream())
                    val answer = ByteArray(input.readUnsignedShort()).also(input::readFully)
                    assertTrue(Message(answer).header.getFlag(org.xbill.DNS.Flags.QR.toInt()))
                }
            } finally { controls.forEach { it.close() } }
        }
    }
    private fun authenticated(relay: SocksRelay): Socket {
        val socket = Socket("127.0.0.1", relay.port).apply { soTimeout = 5000 }
        val output = DataOutputStream(socket.getOutputStream())
        val input = DataInputStream(socket.getInputStream())
        output.write(byteArrayOf(5, 1, 2)); output.flush()
        assertEquals(5, input.readUnsignedByte()); assertEquals(2, input.readUnsignedByte())
        output.writeByte(1); output.writeByte(relay.username.length); output.writeBytes(relay.username)
        output.writeByte(relay.password.length); output.writeBytes(relay.password); output.flush()
        assertEquals(1, input.readUnsignedByte()); assertEquals(0, input.readUnsignedByte())
        return socket
    }
    private fun request(socket: Socket, command: Int = 1, host: String = "example.test", port: Int = 443, early: String = ""): Int {
        val output = DataOutputStream(socket.getOutputStream())
        output.write(byteArrayOf(5, command.toByte(), 0, 3)); output.writeByte(host.length); output.writeBytes(host); output.writeShort(port)
        output.writeBytes(early); output.flush()
        val input = DataInputStream(socket.getInputStream())
        assertEquals(5, input.readUnsignedByte()); assertEquals(0, input.readUnsignedByte()); assertEquals(0, input.readUnsignedByte())
        SocksRelay.readAddress(input)
        return input.readUnsignedShort()
    }

    @Test(timeout = 15000) fun httpHeadersEarlyDataAndHalfCloseRemainIntact() {
        ServerSocket(0, 10, InetAddress.getLoopbackAddress()).use { upstream ->
            val failure = AtomicReference<Throwable?>()
            val server = thread {
                try { upstream.accept().use { socket ->
                    socket.soTimeout = 5000
                    val input = socket.getInputStream()
                    val header = StringBuilder()
                    while (!header.endsWith("\r\n\r\n")) header.append(input.read().toChar())
                    assertTrue(header.startsWith("CONNECT example.test:443 HTTP/1.1"))
                    val output = socket.getOutputStream()
                    for (byte in "HTTP/1.1 200 Connection established\r\n\r\nserver-prefix".toByteArray()) { output.write(byte.toInt()); output.flush() }
                    val body = input.readBytes()
                    assertEquals("client-first", body.toString(Charsets.UTF_8))
                    output.write("server-after-half-close".toByteArray()); output.flush()
                } } catch (error: Throwable) { failure.set(error) }
            }
            SocksRelay(Endpoint("127.0.0.1", upstream.localPort), ProxyKind.HTTP_CONNECT) { _, _ -> error("DNS was not requested") }.use { relay ->
                authenticated(relay).use { socket ->
                    request(socket, early = "client-first")
                    socket.shutdownOutput()
                    assertEquals("server-prefixserver-after-half-close", socket.getInputStream().readBytes().toString(Charsets.UTF_8))
                }
            }
            server.join(5000); assertFalse(server.isAlive); failure.get()?.let { throw it }
        }
    }

    @Test(timeout = 15000) fun socksBackendPreservesIpv6AndPayload() {
        ServerSocket(0, 10, InetAddress.getLoopbackAddress()).use { upstream ->
            val failure = AtomicReference<Throwable?>()
            val server = thread {
                try { upstream.accept().use { socket ->
                    socket.soTimeout = 5000
                    val input = DataInputStream(socket.getInputStream())
                    val output = DataOutputStream(socket.getOutputStream())
                    assertArrayEquals(byteArrayOf(5, 1, 0), ByteArray(3).also(input::readFully))
                    output.write(byteArrayOf(5, 0)); output.flush()
                    assertArrayEquals(byteArrayOf(5, 1, 0), ByteArray(3).also(input::readFully))
                    assertEquals(InetAddress.getByName("2001:db8::1"), InetAddress.getByName(SocksRelay.readAddress(input)))
                    assertEquals(443, input.readUnsignedShort())
                    output.write(byteArrayOf(5, 0, 0, 1, 127, 0, 0, 1)); output.writeShort(1234); output.flush()
                    val body = ByteArray(4).also(input::readFully); output.write(body); output.flush()
                } } catch (error: Throwable) { failure.set(error) }
            }
            SocksRelay(Endpoint("127.0.0.1", upstream.localPort), ProxyKind.SOCKS5) { _, _ -> error("DNS was not requested") }.use { relay ->
                authenticated(relay).use { socket ->
                    val output = DataOutputStream(socket.getOutputStream())
                    output.write(byteArrayOf(5, 1, 0, 4)); output.write(InetAddress.getByName("2001:db8::1").address); output.writeShort(443); output.flush()
                    val input = DataInputStream(socket.getInputStream()); val reply = ByteArray(10).also(input::readFully)
                    assertEquals(0, reply[1].toInt())
                    output.writeBytes("test"); output.flush()
                    assertEquals("test", ByteArray(4).also(input::readFully).toString(Charsets.UTF_8))
                }
            }
            server.join(5000); assertFalse(server.isAlive); failure.get()?.let { throw it }
        }
    }

    @Test(timeout = 15000) fun udpDnsIsHandledLocallyAndOtherUdpIsDropped() {
        // Some build sandboxes deny every UDP send. Skip there instead of
        // reporting a relay failure; ordinary hosts and CI run this test.
        val udpPermitted = runCatching {
            DatagramSocket(0, InetAddress.getLoopbackAddress()).use { receiver ->
                DatagramSocket(0, InetAddress.getLoopbackAddress()).use { sender ->
                    sender.send(DatagramPacket(byteArrayOf(0), 1, InetAddress.getLoopbackAddress(), receiver.localPort))
                }
            }
        }.exceptionOrNull()?.message?.contains("Permission denied") != true
        org.junit.Assume.assumeTrue("Host policy denies loopback UDP", udpPermitted)
        val calls = AtomicInteger()
        SocksRelay(Endpoint("127.0.0.1", 9), ProxyKind.HTTP_CONNECT) { query, reply ->
            calls.incrementAndGet(); reply(TunneledDns.response(Message(query), 0).toWire())
        }.use { relay ->
            DatagramSocket(0, InetAddress.getLoopbackAddress()).use { datagrams ->
                datagrams.soTimeout = 1500
                authenticated(relay).use { control ->
                    val udpPort = request(control, 3, "0.0.0.0", datagrams.localPort)
                    val question = Message.newQuery(org.xbill.DNS.Record.newRecord(Name.fromString("example.test."), Type.A, DClass.IN)).toWire()
                    fun packet(port: Int): ByteArray = java.io.ByteArrayOutputStream().also { buffer ->
                        DataOutputStream(buffer).apply { write(byteArrayOf(0, 0, 0, 1, 8, 8, 8, 8)); writeShort(port); write(question) }
                    }.toByteArray()
                    val query = packet(53)
                    datagrams.send(DatagramPacket(query, query.size, InetAddress.getLoopbackAddress(), udpPort))
                    val answer = DatagramPacket(ByteArray(4096), 4096)
                    datagrams.receive(answer)
                    assertTrue(Message(answer.data.copyOfRange(10, answer.length)).header.getFlag(org.xbill.DNS.Flags.QR.toInt()))
                    assertEquals(1, calls.get())
                    val blocked = packet(443)
                    datagrams.send(DatagramPacket(blocked, blocked.size, InetAddress.getLoopbackAddress(), udpPort))
                    assertThrows(java.net.SocketTimeoutException::class.java) { datagrams.receive(answer) }
                    assertEquals(1, calls.get())
                }
            }
        }
    }

    @Test(timeout = 15000) fun httpConnectFrontendRequiresRelayCredentials() {
        SocksRelay(Endpoint("127.0.0.1", 9), ProxyKind.HTTP_CONNECT) { _, _ -> error("DNS was not requested") }.use { relay ->
            Socket("127.0.0.1", relay.port).use { socket ->
                socket.soTimeout = 5000
                socket.getOutputStream().write("CONNECT dns.example:443 HTTP/1.1\r\nHost: dns.example:443\r\n\r\n".toByteArray())
                val reply = socket.getInputStream().readBytes().toString(Charsets.US_ASCII)
                assertTrue(reply.startsWith("HTTP/1.1 407 "))
            }
        }
    }

    @Test(timeout = 15000) fun httpConnectFrontendTunnelsThroughTheBackend() {
        ServerSocket(0, 10, InetAddress.getLoopbackAddress()).use { upstream ->
            val failure = AtomicReference<Throwable?>()
            val server = thread {
                try { upstream.accept().use { socket ->
                    socket.soTimeout = 5000
                    val input = DataInputStream(socket.getInputStream())
                    val output = DataOutputStream(socket.getOutputStream())
                    // SOCKS5 backend: the relay translates the HTTP request.
                    assertEquals(5, input.readUnsignedByte()); input.readFully(ByteArray(input.readUnsignedByte()))
                    output.write(byteArrayOf(5, 0)); output.flush()
                    assertEquals(5, input.readUnsignedByte()); assertEquals(1, input.readUnsignedByte()); input.readUnsignedByte()
                    assertEquals("vpn.example", SocksRelay.readAddress(input)); assertEquals(443, input.readUnsignedShort())
                    output.write(byteArrayOf(5, 0, 0, 1, 127, 0, 0, 1, 0, 0)); output.flush()
                    assertEquals("ping", String(ByteArray(4).also(input::readFully)))
                    output.write("pong".toByteArray()); output.flush()
                } } catch (error: Throwable) { failure.set(error) }
            }
            SocksRelay(Endpoint("127.0.0.1", upstream.localPort), ProxyKind.SOCKS5) { _, _ -> error("DNS was not requested") }.use { relay ->
                Socket("127.0.0.1", relay.port).use { socket ->
                    socket.soTimeout = 5000
                    val authorization = java.util.Base64.getEncoder().encodeToString("${relay.username}:${relay.password}".toByteArray())
                    socket.getOutputStream().write(("CONNECT vpn.example:443 HTTP/1.0\r\nProxy-Authorization: Basic $authorization\r\n\r\n").toByteArray())
                    val input = socket.getInputStream()
                    val header = StringBuilder()
                    while (!header.endsWith("\r\n\r\n")) header.append(input.read().toChar())
                    assertTrue(header.startsWith("HTTP/1.1 200 "))
                    socket.getOutputStream().write("ping".toByteArray())
                    assertEquals("pong", String(ByteArray(4).also { DataInputStream(input).readFully(it) }))
                }
            }
            server.join(5000); failure.get()?.let { throw it }
        }
    }

    @Test(timeout = 15000) fun connectionsFromOtherAppsAreClosedBeforeAuthentication() {
        val checked = AtomicInteger()
        SocksRelay(Endpoint("127.0.0.1", 9), ProxyKind.HTTP_CONNECT, ownerCheck = { peer, local ->
            checked.incrementAndGet(); assertTrue(peer.address.isLoopbackAddress && local.port > 0); false
        }) { _, _ -> error("DNS was not requested") }.use { relay ->
            Socket("127.0.0.1", relay.port).use { socket ->
                socket.soTimeout = 5000
                // Closed before any greeting is read or answered.
                assertEquals(-1, socket.getInputStream().read())
            }
            assertEquals(1, checked.get())
        }
    }

    /** Minimal HTTP CONNECT backend: records each request header and echoes. */
    private class HttpBackend(private val stale: (Int) -> Boolean = { false }) : AutoCloseable {
        val server = ServerSocket(0, 50, InetAddress.getLoopbackAddress())
        val headers = java.util.concurrent.LinkedBlockingQueue<String>()
        val connections = AtomicInteger()
        private val worker = thread(isDaemon = true) {
            while (!server.isClosed) {
                val socket = runCatching { server.accept() }.getOrNull() ?: break
                val number = connections.incrementAndGet()
                thread(isDaemon = true) {
                    runCatching { socket.use {
                        val input = it.getInputStream()
                        val header = StringBuilder()
                        while (!header.endsWith("\r\n\r\n")) { val value = input.read(); if (value < 0) return@use; header.append(value.toChar()) }
                        headers.add(header.toString())
                        if (stale(number)) return@use
                        it.getOutputStream().write("HTTP/1.1 200 OK\r\n\r\n".toByteArray())
                        val buffer = ByteArray(1024)
                        while (true) { val count = input.read(buffer); if (count < 0) break; it.getOutputStream().write(buffer, 0, count) }
                    } }
                }
            }
        }
        val endpoint get() = Endpoint("127.0.0.1", server.localPort)
        override fun close() { server.close(); worker.join(1000) }
    }

    private fun echo(relay: SocksRelay, host: String = "example.test", payload: String = "ping") {
        authenticated(relay).use { socket ->
            request(socket, host = host)
            socket.getOutputStream().write(payload.toByteArray())
            assertEquals(payload, String(ByteArray(payload.length).also { DataInputStream(socket.getInputStream()).readFully(it) }))
        }
    }

    @Test(timeout = 15000) fun pipelinedLocalHandshakesAndEarlyDataAreHandled() {
        HttpBackend().use { backend ->
            SocksRelay(backend.endpoint, ProxyKind.HTTP_CONNECT) { _, _ -> error("DNS was not requested") }.use { relay ->
                Socket("127.0.0.1", relay.port).use { socket ->
                    socket.soTimeout = 5000
                    val bytes = java.io.ByteArrayOutputStream()
                    DataOutputStream(bytes).apply {
                        write(byteArrayOf(5, 1, 2))
                        writeByte(1); writeByte(relay.username.length); writeBytes(relay.username); writeByte(relay.password.length); writeBytes(relay.password)
                        write(byteArrayOf(5, 1, 0, 3, 12)); writeBytes("example.test"); writeShort(443)
                        writeBytes("early")
                    }
                    socket.getOutputStream().write(bytes.toByteArray())
                    val input = DataInputStream(socket.getInputStream())
                    assertArrayEquals(byteArrayOf(5, 2, 1, 0), ByteArray(4).also(input::readFully))
                    assertEquals(0, ByteArray(10).also(input::readFully)[1].toInt())
                    assertEquals("early", String(ByteArray(5).also(input::readFully)))
                }
            }
        }
    }

    @Test(timeout = 15000) fun socksUpstreamIsPipelinedWithCredentialsAndAddressTypes() {
        ServerSocket(0, 10, InetAddress.getLoopbackAddress()).use { upstream ->
            val failure = AtomicReference<Throwable?>()
            val server = thread {
                try { upstream.accept().use { socket ->
                    socket.soTimeout = 5000
                    val input = DataInputStream(socket.getInputStream())
                    // Everything arrives before any answer is sent.
                    val expected = 3 + 3 + 4 + 6 + 4 + 4 + 2
                    val request = ByteArray(expected).also(input::readFully)
                    assertArrayEquals(byteArrayOf(5, 1, 2, 1, 4) + "user".toByteArray() + byteArrayOf(6) + "secret".toByteArray() +
                        byteArrayOf(5, 1, 0, 1, 192.toByte(), 0, 2, 10, 1, 187.toByte()), request)
                    socket.getOutputStream().write(byteArrayOf(5, 2, 1, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0) + "pong".toByteArray())
                    socket.getOutputStream().flush()
                    Thread.sleep(200)
                } } catch (error: Throwable) { failure.set(error) }
            }
            SocksRelay(Endpoint("127.0.0.1", upstream.localPort), ProxyKind.SOCKS5, upstreamCredentials = "user" to "secret") { _, _ ->
                error("DNS was not requested")
            }.use { relay ->
                authenticated(relay).use { socket ->
                    val output = DataOutputStream(socket.getOutputStream())
                    output.write(byteArrayOf(5, 1, 0, 1, 192.toByte(), 0, 2, 10)); output.writeShort(443); output.flush()
                    val input = DataInputStream(socket.getInputStream())
                    assertEquals(0, ByteArray(10).also(input::readFully)[1].toInt())
                    assertEquals("pong", String(ByteArray(4).also(input::readFully)))
                }
            }
            server.join(5000); failure.get()?.let { throw it }
        }
    }

    @Test(timeout = 15000) fun httpBackendCredentialsAndSyntheticNamesAreSentUpstream() {
        HttpBackend().use { backend ->
            SocksRelay(backend.endpoint, ProxyKind.HTTP_CONNECT, upstreamCredentials = "user" to "secret",
                target = { if (it == "198.18.128.1") "named.example" else if (it.startsWith("198.18.")) error("unknown") else it }) { _, _ ->
                error("DNS was not requested")
            }.use { relay ->
                echo(relay, host = "198.18.128.1")
                val header = backend.headers.poll(5, TimeUnit.SECONDS)!!
                assertTrue(header.startsWith("CONNECT named.example:443 HTTP/1.1\r\n"))
                assertTrue(header.contains("Proxy-Authorization: " + okhttp3.Credentials.basic("user", "secret")))
                authenticated(relay).use { socket ->
                    val output = DataOutputStream(socket.getOutputStream())
                    output.write(byteArrayOf(5, 1, 0, 3, 12)); output.writeBytes("198.18.200.9"); output.writeShort(443); output.flush()
                    val input = DataInputStream(socket.getInputStream())
                    assertEquals(5, input.readUnsignedByte()); assertEquals(4, input.readUnsignedByte())
                }
            }
        }
    }

    @Test(timeout = 15000) fun sessionsBeyondTheLimitAreRefused() {
        SocksRelay(Endpoint("127.0.0.1", 9), ProxyKind.HTTP_CONNECT, maxSessions = 2) { _, _ -> error("DNS was not requested") }.use { relay ->
            val held = listOf(authenticated(relay), authenticated(relay))
            try {
                Socket("127.0.0.1", relay.port).use { extra ->
                    extra.soTimeout = 5000
                    assertEquals(-1, extra.getInputStream().read())
                }
            } finally { held.forEach { it.close() } }
        }
    }

    @Test(timeout = 20000) fun warmConnectionsAreReusedAndStaleOnesRetried() {
        // Connection 2 is a warm connection the "server" has silently dropped.
        HttpBackend(stale = { it == 2 }).use { backend ->
            SocksRelay(backend.endpoint, ProxyKind.HTTP_CONNECT, keepWarm = { true }) { _, _ -> error("DNS was not requested") }.use { relay ->
                echo(relay)
                val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
                while (backend.connections.get() < 3 && System.nanoTime() < deadline) Thread.sleep(50)
                assertEquals("Two warm connections follow recent traffic", 3, backend.connections.get())
                echo(relay, payload = "second")
                echo(relay, payload = "third")
                // Requests 2 and 3 used the warm connections; the stale one was retried on a new connection.
                assertTrue(backend.connections.get() in 4..6)
                assertEquals(4, generateSequence { backend.headers.poll() }.count())
            }
        }
    }
}
