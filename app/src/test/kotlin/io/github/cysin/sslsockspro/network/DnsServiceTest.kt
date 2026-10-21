package io.github.cysin.sslsockspro.network

import io.github.cysin.sslsockspro.config.Endpoint
import io.github.cysin.sslsockspro.model.ProxyKind
import org.junit.Assert.*
import org.junit.Test
import org.xbill.DNS.ARecord
import org.xbill.DNS.DClass
import org.xbill.DNS.Flags
import org.xbill.DNS.Message
import org.xbill.DNS.Name
import org.xbill.DNS.Rcode
import org.xbill.DNS.Record
import org.xbill.DNS.Section
import org.xbill.DNS.Type
import java.net.InetAddress
import java.net.ServerSocket
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

class DnsServiceTest {
    private fun query(name: String, type: Int, id: Int = 7): ByteArray =
        Message.newQuery(Record.newRecord(Name.fromString("$name."), type, DClass.IN)).apply { header.id = id }.toWire()

    private fun answer(query: ByteArray, ttl: Long = 300): ByteArray {
        val message = Message(query)
        return TunneledDns.response(message, Rcode.NOERROR).apply {
            addRecord(ARecord(message.question.name, DClass.IN, ttl, InetAddress.getByName("192.0.2.10")), Section.ANSWER)
        }.toWire()
    }

    private class Upstream(private val respond: (ByteArray) -> ByteArray) : (ByteArray, (ByteArray) -> Unit) -> Unit {
        val queries = mutableListOf<ByteArray>()
        override fun invoke(query: ByteArray, reply: (ByteArray) -> Unit) { queries += query; reply(respond(query)) }
    }

    private fun resolve(service: DnsService, query: ByteArray): Message {
        var result: ByteArray? = null
        service.resolve(query) { result = it }
        return Message(result!!)
    }

    @Test fun blockedIpv6AndCachedAnswersNeedNoUpstreamQuery() {
        var now = 0L
        val upstream = Upstream { answer(it) }
        val service = DnsService(upstream, DnsCache(clock = { now }), null, ipv6 = false)
        val aaaa = resolve(service, query("example.org", Type.AAAA))
        assertEquals(Rcode.NOERROR, aaaa.rcode)
        assertEquals(0, aaaa.getSection(Section.ANSWER).size)
        assertTrue(upstream.queries.isEmpty())
        resolve(service, query("example.org", Type.A, id = 1))
        now += TimeUnit.SECONDS.toNanos(100)
        val cached = resolve(service, query("Example.ORG", Type.A, id = 2))
        assertEquals(1, upstream.queries.size)
        assertEquals(2, cached.header.id)
        assertEquals(200L, cached.getSection(Section.ANSWER).single().ttl)
        now += TimeUnit.SECONDS.toNanos(201)
        resolve(service, query("example.org", Type.A, id = 3))
        assertEquals("An expired answer is fetched again", 2, upstream.queries.size)
    }

    @Test fun failuresAreNotCachedAndNegativeAnswersExpireQuickly() {
        var now = 0L
        val cache = DnsCache(clock = { now })
        val failing = Upstream { TunneledDns.failure(it) }
        val service = DnsService(failing, cache, null, ipv6 = true)
        resolve(service, query("down.example", Type.A)); resolve(service, query("down.example", Type.A))
        assertEquals(2, failing.queries.size)
        val missing = Upstream { TunneledDns.response(Message(it), Rcode.NXDOMAIN).toWire() }
        val negative = DnsService(missing, DnsCache(clock = { now }), null, ipv6 = true)
        resolve(negative, query("missing.example", Type.A)); resolve(negative, query("missing.example", Type.A))
        assertEquals(1, missing.queries.size)
        now += TimeUnit.SECONDS.toNanos(31)
        resolve(negative, query("missing.example", Type.A))
        assertEquals(2, missing.queries.size)
    }

    @Test fun proxyResolutionSynthesizesAddressesAndMapsThemBack() {
        val upstream = Upstream { answer(it) }
        val names = FakeDns()
        val service = DnsService(upstream, DnsCache(), names, ipv6 = true)
        val first = resolve(service, query("Example.org", Type.A)).getSection(Section.ANSWER).single() as ARecord
        val again = resolve(service, query("example.org", Type.A)).getSection(Section.ANSWER).single() as ARecord
        val v6 = resolve(service, query("example.org", Type.AAAA)).getSection(Section.ANSWER).single().rdataToString()
        assertEquals(first.address, again.address)
        assertTrue(first.address.hostAddress!!.startsWith("198.18."))
        assertEquals("example.org", names.target(first.address.hostAddress!!))
        assertEquals("example.org", names.target(v6))
        assertEquals("203.0.113.5", names.target("203.0.113.5"))
        assertThrows(IllegalArgumentException::class.java) { names.target("198.18.250.250") }
        assertEquals(0, resolve(service, query("example.org", Type.HTTPS)).getSection(Section.ANSWER).size)
        assertTrue("Address queries never reach a resolver", upstream.queries.isEmpty())
        resolve(service, query("example.org", Type.MX))
        resolve(service, query("localhost", Type.A))
        resolve(service, query("printer.local", Type.A))
        assertEquals("Other types and local names use real DNS", 3, upstream.queries.size)
    }

    @Test fun exhaustedSyntheticRangesReuseTheLeastRecentlyUsedAddress() {
        var now = 0L
        val names = FakeDns(capacity = 2, clock = { now })
        fun address(name: String) = (Message(names.answer(Message(query(name, Type.A)))!!).getSection(Section.ANSWER).single() as ARecord).address.hostAddress!!
        val one = address("one.example"); now++
        val two = address("two.example"); now++
        names.target(one); now++
        assertEquals(two, address("three.example"))
        assertEquals("one.example", names.target(one))
        assertThrows(IllegalArgumentException::class.java) { names.target("198.18.128.200") }
    }

    @Test(timeout = 15000) fun backendProbeIdentifiesHttpAndSocksButNotSilence() {
        fun server(answer: (java.net.Socket) -> Unit): ServerSocket = ServerSocket(0, 5, InetAddress.getLoopbackAddress()).also { socket ->
            thread(isDaemon = true) { while (!socket.isClosed) runCatching { socket.accept().use(answer) } }
        }
        server { it.getInputStream().read(); it.getOutputStream().write("HTTP/1.1 400 Bad Request\r\n\r\n".toByteArray()) }.use {
            assertEquals(ProxyKind.HTTP_CONNECT, BackendProbe.detect(Endpoint("127.0.0.1", it.localPort)))
        }
        server { socket ->
            // A SOCKS5 server closes on the HTTP probe and answers its own greeting.
            val first = socket.getInputStream().read()
            if (first == 5) { socket.getInputStream().read(ByteArray(2)); socket.getOutputStream().write(byteArrayOf(5, 0)); Thread.sleep(300) }
        }.use { assertEquals(ProxyKind.SOCKS5, BackendProbe.detect(Endpoint("127.0.0.1", it.localPort), timeoutMillis = 1000)) }
        server { }.use { assertNull("An unreachable backend is not a SOCKS5 server", BackendProbe.detect(Endpoint("127.0.0.1", it.localPort), timeoutMillis = 1000)) }
    }

    @Test fun cachedAnswersKeepTheRecursionFlagOfTheQuery() {
        val service = DnsService(Upstream { answer(it) }, DnsCache(), null, ipv6 = true)
        resolve(service, query("example.org", Type.A))
        val withoutRecursion = Message.newQuery(Record.newRecord(Name.fromString("example.org."), Type.A, DClass.IN)).apply {
            header.unsetFlag(Flags.RD.toInt())
        }.toWire()
        assertFalse(resolve(service, withoutRecursion).header.getFlag(Flags.RD.toInt()))
    }
}
