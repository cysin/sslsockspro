package io.github.cysin.sslsockspro.network

import io.github.cysin.sslsockspro.config.Endpoint
import io.github.cysin.sslsockspro.model.ProxyKind
import okhttp3.Call
import okhttp3.Callback
import okhttp3.Dispatcher
import okhttp3.Dns
import okhttp3.Interceptor
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import org.xbill.DNS.EDNSOption
import org.xbill.DNS.ExtendedFlags
import org.xbill.DNS.Flags
import org.xbill.DNS.GenericEDNSOption
import org.xbill.DNS.Message
import org.xbill.DNS.OPTRecord
import org.xbill.DNS.Opcode
import org.xbill.DNS.Rcode
import org.xbill.DNS.Section
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.UnknownHostException
import java.util.concurrent.TimeUnit

/** DNS has exactly one egress: HTTPS through the selected tunnel. In VPN
 * modes that is the authenticated local relay; [proxyCredentials] are then
 * sent preemptively so the relay never needs an unauthenticated round trip. */
class TunneledDns(
    endpoint: String,
    proxy: Endpoint,
    kind: ProxyKind,
    private val suppressBindings: Boolean,
    proxyCredentials: Pair<String, String>? = null,
) : AutoCloseable {
    private val url = endpoint.toHttpUrl().also {
        require(it.isHttps && it.username.isEmpty() && it.password.isEmpty()) { "DNS must use an HTTPS endpoint without embedded credentials" }
    }
    private val client = OkHttpClient.Builder()
        .proxy(Proxy(if (kind == ProxyKind.HTTP_CONNECT) Proxy.Type.HTTP else Proxy.Type.SOCKS, InetSocketAddress(proxy.host, proxy.port)))
        .apply {
            if (proxyCredentials != null) {
                val authorization = okhttp3.Credentials.basic(proxyCredentials.first, proxyCredentials.second)
                proxyAuthenticator { _, response ->
                    // OkHttp asks preemptively before CONNECT; never retry a rejection.
                    if (response.request.header("Proxy-Authorization") != null) null
                    else response.request.newBuilder().header("Proxy-Authorization", authorization).build()
                }
            }
        }
        .addNetworkInterceptor(withoutUserAgent)
        .dns(Dns { hostname ->
            when (hostname) {
                "127.0.0.1", "localhost" -> listOf(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)))
                "::1" -> listOf(InetAddress.getByAddress(ByteArray(16).also { it[15] = 1 }))
                else -> throw UnknownHostException("Direct DNS lookups are disabled")
            }
        })
        // Apps give up on DNS within seconds. A pooled tunnel connection can be
        // stale after idling; retrying the idempotent query avoids SERVFAIL.
        .connectTimeout(8, TimeUnit.SECONDS).readTimeout(8, TimeUnit.SECONDS).callTimeout(8, TimeUnit.SECONDS)
        // Queries share HTTP/2 connections; concurrency is bounded here and
        // by the relay, not by a fixed pool of blocked threads.
        .dispatcher(Dispatcher().apply { maxRequests = 64; maxRequestsPerHost = 64 })
        .followRedirects(false).followSslRedirects(false).retryOnConnectionFailure(true).build()

    private fun request(query: Message) = Request.Builder().url(url).header("Accept", "application/dns-message")
        .post(query.toWire().toRequestBody("application/dns-message".toMediaType())).build()

    private fun answer(reply: Response, incoming: Message): ByteArray {
        require(reply.isSuccessful && reply.header("Content-Type").orEmpty().substringBefore(';').equals("application/dns-message", true)) { "Encrypted DNS service rejected the request" }
        val bytes = reply.body.byteStream().use { io.github.cysin.sslsockspro.data.PackageImporter.boundedRead(it, 65535) }
        require(bytes.isNotEmpty()) { "Encrypted DNS returned an empty response" }
        return finish(Message(bytes), incoming, suppressBindings)
    }

    /** Blocking lookup, used for health probes. */
    fun resolve(packet: ByteArray): ByteArray {
        val incoming = Message(packet)
        val query = prepare(incoming, suppressBindings) ?: return response(incoming, Rcode.NOERROR).toWire()
        client.newCall(request(query)).execute().use { reply -> return answer(reply, incoming) }
    }

    /** Asynchronous lookup for apps; failures are answered with SERVFAIL. */
    fun resolveAsync(packet: ByteArray, reply: (ByteArray) -> Unit) {
        val incoming = try { Message(packet) } catch (_: Exception) { reply(failure(packet)); return }
        val query = try { prepare(incoming, suppressBindings) } catch (_: Exception) { reply(failure(packet)); return }
        if (query == null) { reply(response(incoming, Rcode.NOERROR).toWire()); return }
        client.newCall(request(query)).enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) = reply(failure(packet))
            override fun onResponse(call: Call, response: Response) {
                reply(response.use { runCatching { answer(it, incoming) }.getOrElse { failure(packet) } })
            }
        })
    }

    override fun close() {
        client.dispatcher.cancelAll(); client.connectionPool.evictAll()
        client.dispatcher.executorService.shutdown()
    }

    fun cancelPending() = client.dispatcher.cancelAll()
    fun evictConnections() = client.connectionPool.evictAll()

    companion object {
        private const val PADDING_BLOCK = 128

        /** OkHttp's default User-Agent would identify the client software to the DoH operator. */
        internal val withoutUserAgent = Interceptor { chain -> chain.proceed(chain.request().newBuilder().removeHeader("User-Agent").build()) }

        /** The query actually sent: single question, transaction ID 0, no
         * identifying EDNS options (such as client subnet), DO/RD/CD preserved
         * and padded to a block size (RFC 8467). Null when answered locally. */
        internal fun prepare(incoming: Message, suppressBindings: Boolean): Message? {
            require(!incoming.header.getFlag(Flags.QR.toInt()) && incoming.header.opcode == Opcode.QUERY &&
                incoming.header.getCount(Section.QUESTION) == 1) { "Only single-question DNS lookups are supported" }
            if (suppressBindings && incoming.question.type in setOf(64, 65)) return null
            val dnssec = incoming.opt?.flags?.and(ExtendedFlags.DO) ?: 0
            val query = Message(0).apply {
                addRecord(incoming.question, Section.QUESTION)
                for (flag in listOf(Flags.RD, Flags.CD)) if (incoming.header.getFlag(flag.toInt())) header.setFlag(flag.toInt())
            }
            val unpadded = OPTRecord(1232, 0, 0, dnssec)
            query.addRecord(unpadded, Section.ADDITIONAL)
            // A padding option adds four bytes of header plus its content.
            val padding = (PADDING_BLOCK - (query.toWire().size + 4) % PADDING_BLOCK) % PADDING_BLOCK
            query.removeRecord(unpadded, Section.ADDITIONAL)
            query.addRecord(OPTRecord(1232, 0, 0, dnssec, listOf(GenericEDNSOption(EDNSOption.Code.PADDING, ByteArray(padding)))), Section.ADDITIONAL)
            return query
        }

        /** Restores the client's transaction ID and removes EDNS data and,
         * when suppressed, service-binding records without keeping AD. */
        internal fun finish(answer: Message, incoming: Message, suppressBindings: Boolean): ByteArray {
            require(answer.header.getFlag(Flags.QR.toInt()) && answer.question == incoming.question) { "Encrypted DNS returned an unrelated response" }
            answer.header.id = incoming.header.id
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

        fun response(query: Message, code: Int): Message = Message(query.header.id).apply {
            header.setFlag(Flags.QR.toInt()); header.setFlag(Flags.RA.toInt())
            if (query.header.getFlag(Flags.RD.toInt())) header.setFlag(Flags.RD.toInt())
            header.rcode = code
            query.question?.let { addRecord(it, Section.QUESTION) }
        }
        fun failure(packet: ByteArray): ByteArray = runCatching { response(Message(packet), Rcode.SERVFAIL).toWire() }.getOrDefault(byteArrayOf())
    }
}
