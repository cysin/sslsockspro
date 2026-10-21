package io.github.cysin.sslsockspro.engine

/** Token bucket for native diagnostics. Startup bursts are kept; a flood is
 * summarized instead of silently ending all later diagnostics. */
class LogLimiter(
    private val burst: Int = 200,
    private val perSecond: Int = 20,
    private val clock: () -> Long = System::nanoTime,
) {
    private var tokens = burst.toDouble()
    private var updated = clock()
    private var suppressed = 0L

    /** Returns the lines to emit for [line], including a pending summary. */
    @Synchronized fun admit(line: String): List<String> {
        val now = clock()
        tokens = minOf(burst.toDouble(), tokens + (now - updated) / 1_000_000_000.0 * perSecond)
        updated = now
        val needed = if (suppressed > 0) 2 else 1
        if (tokens < needed) { suppressed++; return emptyList() }
        tokens -= needed
        val summary = if (suppressed > 0) listOf("$suppressed native log lines were suppressed") else emptyList()
        suppressed = 0
        return summary + line
    }
}
