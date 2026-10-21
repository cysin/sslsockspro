package io.github.cysin.sslsockspro.network

import io.github.cysin.sslsockspro.config.Endpoint
import io.github.cysin.sslsockspro.model.ProxyKind
import okhttp3.OkHttpClient
import okhttp3.Request
import org.junit.Assert.*
import org.junit.Test
import org.xbill.DNS.ARecord
import org.xbill.DNS.ClientSubnetOption
import org.xbill.DNS.DClass
import org.xbill.DNS.EDNSOption
import org.xbill.DNS.ExtendedFlags
import org.xbill.DNS.Flags
import org.xbill.DNS.HTTPSRecord
import org.xbill.DNS.Message
import org.xbill.DNS.Name
import org.xbill.DNS.OPTRecord
import org.xbill.DNS.Record
import org.xbill.DNS.Section
import org.xbill.DNS.Type
import java.net.InetAddress
import java.net.ServerSocket
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread

class TunneledDnsTest {
    private val name = Name.fromString("example.test.")
    private fun query(type: Int): Message = Message.newQuery(Record.newRecord(name, type, DClass.IN)).apply {
        header.id = 0x1234
        addRecord(OPTRecord(4096, 0, 0, ExtendedFlags.DO,
            listOf(ClientSubnetOption(24, InetAddress.getByName("203.0.113.0")))), Section.ADDITIONAL)
    }

    @Test fun queriesAreNeutralizedAndPaddedToBlocks() {
        for (type in listOf(Type.A, Type.AAAA, Type.MX)) {
            val prepared = TunneledDns.prepare(query(type), suppressBindings = true)!!
            assertEquals(0, prepared.header.id)
            assertEquals(0, prepared.toWire().size % 128)
            val options = prepared.opt.options
            assertTrue(options.none { it.code == EDNSOption.Code.CLIENT_SUBNET })
            assertEquals(listOf(EDNSOption.Code.PADDING), options.map { it.code })
            assertEquals(ExtendedFlags.DO, prepared.opt.flags and ExtendedFlags.DO)
            assertTrue(prepared.header.getFlag(Flags.RD.toInt()))
        }
        assertNull(TunneledDns.prepare(query(Type.HTTPS), suppressBindings = true))
        assertNotNull(TunneledDns.prepare(query(Type.HTTPS), suppressBindings = false))
    }

    @Test fun answersRegainTheClientIdAndLoseServiceBindingsAndEdns() {
        val incoming = query(Type.A)
        val answer = Message(0).apply {
            header.setFlag(Flags.QR.toInt()); header.setFlag(Flags.AD.toInt())
            addRecord(incoming.question, Section.QUESTION)
            addRecord(ARecord(name, DClass.IN, 60, InetAddress.getByName("192.0.2.10")), Section.ANSWER)
            addRecord(HTTPSRecord(name, DClass.IN, 60, 1, Name.root, emptyList()), Section.ANSWER)
            addRecord(OPTRecord(1232, 0, 0), Section.ADDITIONAL)
        }
        val finished = Message(TunneledDns.finish(answer, incoming, suppressBindings = true))
        assertEquals(0x1234, finished.header.id)
        assertNull(finished.opt)
        assertEquals(listOf(Type.A), finished.getSection(Section.ANSWER).map { it.type })
        assertFalse("AD must not survive edited records", finished.header.getFlag(Flags.AD.toInt()))
        val unrelated = Message(0).apply { header.setFlag(Flags.QR.toInt()); addRecord(query(Type.MX).question, Section.QUESTION) }
        assertThrows(IllegalArgumentException::class.java) { TunneledDns.finish(unrelated, incoming, suppressBindings = true) }
    }

    @Test(timeout = 15000) fun relayCredentialsArePreemptiveOnTheFirstConnect() {
        ServerSocket(0).use { proxy ->
            val request = AtomicReference<String>()
            val server = thread {
                proxy.accept().use { client ->
                    val text = StringBuilder()
                    val input = client.getInputStream()
                    while (!text.endsWith("\r\n\r\n")) text.append(input.read().toChar())
                    request.set(text.toString())
                    client.getOutputStream().write("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".toByteArray())
                }
            }
            TunneledDns("https://dns.example/dns-query", Endpoint("127.0.0.1", proxy.localPort), ProxyKind.HTTP_CONNECT, true,
                "vpn" to "secret").use { dns ->
                assertThrows(Exception::class.java) { dns.resolve(query(Type.A).toWire()) }
            }
            server.join(5000)
            val connect = request.get()
            assertTrue(connect.startsWith("CONNECT dns.example:443 HTTP/1.1\r\n"))
            assertTrue(connect.contains("Proxy-Authorization: " + okhttp3.Credentials.basic("vpn", "secret")))
        }
    }

    @Test(timeout = 15000) fun requestsCarryNoUserAgent() {
        ServerSocket(0).use { server ->
            val headers = AtomicReference<String>()
            val worker = thread {
                server.accept().use { client ->
                    val text = StringBuilder()
                    val input = client.getInputStream()
                    while (!text.endsWith("\r\n\r\n")) text.append(input.read().toChar())
                    headers.set(text.toString())
                    client.getOutputStream().write("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n".toByteArray())
                }
            }
            val client = OkHttpClient.Builder().addNetworkInterceptor(TunneledDns.withoutUserAgent).build()
            client.newCall(Request.Builder().url("http://127.0.0.1:${server.localPort}/").build()).execute().close()
            worker.join(5000)
            assertFalse(headers.get().contains("User-Agent", ignoreCase = true))
            client.dispatcher.executorService.shutdown()
        }
    }
}
