package io.github.cysin.sslsockspro.network

import io.github.cysin.sslsockspro.config.Endpoint
import io.github.cysin.sslsockspro.model.ProxyKind
import okhttp3.Dns
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.xbill.DNS.ExtendedFlags
import org.xbill.DNS.Flags
import org.xbill.DNS.Message
import org.xbill.DNS.OPTRecord
import org.xbill.DNS.Opcode
import org.xbill.DNS.Rcode
import org.xbill.DNS.Section
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.UnknownHostException
import java.util.concurrent.TimeUnit

/** DNS has exactly one egress: HTTPS through the selected local stunnel proxy. */
class TunneledDns(endpoint: String, proxy: Endpoint, kind: ProxyKind, private val suppressBindings: Boolean) : AutoCloseable {
    private val url = endpoint.toHttpUrl().also {
        require(it.isHttps && it.username.isEmpty() && it.password.isEmpty()) { "DNS must use an HTTPS endpoint without embedded credentials" }
    }
    private val client = OkHttpClient.Builder()
        .proxy(Proxy(if (kind == ProxyKind.HTTP_CONNECT) Proxy.Type.HTTP else Proxy.Type.SOCKS, InetSocketAddress(proxy.host, proxy.port)))
        .dns(Dns { hostname ->
            when (hostname) {
                "127.0.0.1", "localhost" -> listOf(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)))
                "::1" -> listOf(InetAddress.getByAddress(ByteArray(16).also { it[15] = 1 }))
                else -> throw UnknownHostException("Direct DNS lookups are disabled")
            }
        })
        .connectTimeout(15, TimeUnit.SECONDS).readTimeout(30, TimeUnit.SECONDS).callTimeout(30, TimeUnit.SECONDS)
        .followRedirects(false).followSslRedirects(false).retryOnConnectionFailure(false).build()

    fun resolve(packet: ByteArray): ByteArray {
        val incoming = Message(packet)
        require(!incoming.header.getFlag(Flags.QR.toInt()) && incoming.header.opcode == Opcode.QUERY &&
            incoming.header.getCount(Section.QUESTION) == 1) { "Only single-question DNS lookups are supported" }
        val question = incoming.question
        if (suppressBindings && question.type in setOf(64, 65)) return response(incoming, Rcode.NOERROR).toWire()
        // Reconstruct OPT without options: client subnet and identifying EDNS
        // extensions must not cross the tunnel. Preserve DNSSEC's DO bit.
        val dnssec = incoming.opt?.flags?.and(ExtendedFlags.DO) ?: 0
        val query = Message(0).apply {
            addRecord(question, Section.QUESTION)
            for (flag in listOf(Flags.RD, Flags.CD)) if (incoming.header.getFlag(flag.toInt())) header.setFlag(flag.toInt())
        }
        query.addRecord(OPTRecord(1232, 0, 0, dnssec), Section.ADDITIONAL)
        val originalId = incoming.header.id
        val request = Request.Builder().url(url).header("Accept", "application/dns-message")
            .post(query.toWire().toRequestBody("application/dns-message".toMediaType())).build()
        client.newCall(request).execute().use { reply ->
            require(reply.isSuccessful && reply.header("Content-Type").orEmpty().substringBefore(';').equals("application/dns-message", true)) { "Encrypted DNS service rejected the request" }
            val bytes = reply.body?.byteStream()?.use { io.github.cysin.sslsockspro.data.PackageImporter.boundedRead(it, 65535) }
                ?: throw IllegalArgumentException("Encrypted DNS returned an empty response")
            val answer = Message(bytes)
            require(answer.header.getFlag(Flags.QR.toInt()) && answer.question == question) { "Encrypted DNS returned an unrelated response" }
            answer.header.id = originalId
            answer.getSection(Section.ADDITIONAL).filterIsInstance<OPTRecord>().forEach { answer.removeRecord(it, Section.ADDITIONAL) }
            if (suppressBindings) {
                var changed = false
                for (section in listOf(Section.ANSWER, Section.AUTHORITY, Section.ADDITIONAL)) {
                    answer.getSection(section).filter { it.type in setOf(64, 65) }.forEach { answer.removeRecord(it, section); changed = true }
                }
                if (changed) answer.header.unsetFlag(Flags.AD.toInt())
            }
            return answer.toWire()
        }
    }

    override fun close() {
        client.dispatcher.cancelAll(); client.connectionPool.evictAll()
        client.dispatcher.executorService.shutdown()
    }

    fun cancelPending() = client.dispatcher.cancelAll()

    companion object {
        fun response(query: Message, code: Int): Message = Message(query.header.id).apply {
            header.setFlag(Flags.QR.toInt()); header.setFlag(Flags.RA.toInt())
            if (query.header.getFlag(Flags.RD.toInt())) header.setFlag(Flags.RD.toInt())
            header.rcode = code
            query.question?.let { addRecord(it, Section.QUESTION) }
        }
        fun failure(packet: ByteArray): ByteArray = runCatching { response(Message(packet), Rcode.SERVFAIL).toWire() }.getOrDefault(byteArrayOf())
    }
}
