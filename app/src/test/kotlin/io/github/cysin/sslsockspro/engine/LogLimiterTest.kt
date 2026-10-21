package io.github.cysin.sslsockspro.engine

import org.junit.Assert.assertEquals
import org.junit.Test

class LogLimiterTest {
    @Test fun burstIsKeptFloodIsSummarizedAndLaterLinesSurvive() {
        var now = 0L
        val limiter = LogLimiter(burst = 3, perSecond = 1) { now }
        assertEquals(listOf("line 1", "line 2", "line 3"), (1..5).flatMap { limiter.admit("line $it") })
        now += 2_000_000_000L
        assertEquals(listOf("2 native log lines were suppressed", "line 6"), limiter.admit("line 6"))
        assertEquals(emptyList<String>(), limiter.admit("line 7"))
        now += 10_000_000_000L
        assertEquals(listOf("1 native log lines were suppressed", "line 8"), limiter.admit("line 8"))
    }
}
