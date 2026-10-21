package io.github.cysin.sslsockspro.network

import io.github.cysin.sslsockspro.config.Endpoint
import io.github.cysin.sslsockspro.model.ProxyKind
import java.net.InetSocketAddress
import java.net.Socket

/** Identifies the proxy protocol behind stunnel. HTTP proxies answer a
 * complete request; SOCKS5 servers close on its first byte and answer their
 * own greeting with version 5. Only positive answers are trusted: a closed
 * connection alone may just mean the server is unreachable. */
object BackendProbe {
    fun detect(endpoint: Endpoint, timeoutMillis: Int = 4000): ProxyKind? {
        val http = exchange(endpoint, timeoutMillis, "CONNECT 0.0.0.0:1 HTTP/1.1\r\nHost: 0.0.0.0:1\r\n\r\n".toByteArray(Charsets.US_ASCII))
        if (http != null && http.size >= 5 && String(http, 0, 5, Charsets.US_ASCII) == "HTTP/") return ProxyKind.HTTP_CONNECT
        if (http != null && http.firstOrNull()?.toInt() == 5) return ProxyKind.SOCKS5
        if (http == null || http.isNotEmpty()) return null
        val socks = exchange(endpoint, timeoutMillis, byteArrayOf(5, 1, 0))
        return if (socks != null && socks.size >= 2 && socks[0].toInt() == 5) ProxyKind.SOCKS5 else null
    }

    /** First bytes of the answer; empty when closed without data; null on timeout or error. */
    private fun exchange(endpoint: Endpoint, timeoutMillis: Int, request: ByteArray): ByteArray? = runCatching {
        Socket().use { socket ->
            socket.connect(InetSocketAddress(endpoint.host, endpoint.port), timeoutMillis)
            socket.soTimeout = timeoutMillis
            socket.getOutputStream().apply { write(request); flush() }
            val buffer = ByteArray(5)
            var count = 0
            while (count < buffer.size) {
                // A SOCKS5 server answers its greeting with two bytes and waits.
                val read = try { socket.getInputStream().read(buffer, count, buffer.size - count) }
                    catch (timeout: java.net.SocketTimeoutException) { if (count > 0) break else throw timeout }
                if (read < 0) break
                count += read
            }
            buffer.copyOf(count)
        }
    }.getOrNull()
}
