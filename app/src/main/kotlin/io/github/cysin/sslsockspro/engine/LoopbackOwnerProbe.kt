package io.github.cysin.sslsockspro.engine

/** VPN UID ranges can reach the owner lookup asynchronously after establish().
 * Wait for them before classifying a platform as unable to attribute clients.
 * Once attribution has worked, never downgrade that process to an open guard. */
internal class LoopbackOwnerProbe(
    private val nowMillis: () -> Long = { System.nanoTime() / 1_000_000 },
    private val pause: (Long) -> Unit = Thread::sleep,
    private val timeoutMillis: Long = 2_000,
) {
    private var verified = false

    @Synchronized fun available(owned: () -> Boolean): Boolean {
        val deadline = nowMillis() + timeoutMillis
        while (true) {
            if (owned()) { verified = true; return true }
            val remaining = deadline - nowMillis()
            if (remaining <= 0) {
                check(!verified) { "Android is not ready to verify internal clients; reconnect the tunnel" }
                return false
            }
            // Interrupted startup must abort, never disable the guard.
            pause(minOf(25, remaining))
        }
    }
}
