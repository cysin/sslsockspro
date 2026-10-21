package io.github.cysin.sslsockspro.engine

import org.junit.Assert.*
import org.junit.Test

class LoopbackOwnerProbeTest {
    @Test fun vpnReplacementWaitsForOwnerAttribution() {
        var now = 0L
        val probe = LoopbackOwnerProbe({ now }, { now += it })
        assertTrue(probe.available { now >= 100 })
        assertEquals(100L, now)
        // Replacing the TUN can briefly remove the UID range again.
        assertTrue(probe.available { now >= 200 })
        assertEquals(200L, now)
    }

    @Test fun permanentlyUnsupportedPlatformHasABoundedProbe() {
        var now = 0L
        val probe = LoopbackOwnerProbe({ now }, { now += it })
        assertFalse(probe.available { false })
        assertEquals(2_000L, now)
    }

    @Test fun verifiedPlatformNeverSilentlyDisablesTheGuard() {
        var now = 0L
        val probe = LoopbackOwnerProbe({ now }, { now += it })
        assertTrue(probe.available { true })
        assertThrows(IllegalStateException::class.java) { probe.available { false } }
        assertTrue(probe.available { true })
    }

    @Test fun cancelledProbeDoesNotBecomeAnUnsupportedPlatform() {
        val probe = LoopbackOwnerProbe({ 0L }, { throw InterruptedException("cancelled") })
        assertThrows(InterruptedException::class.java) { probe.available { false } }
        assertTrue(probe.available { true })
    }
}
