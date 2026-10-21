package io.github.cysin.sslsockspro.ui

import org.junit.Assert.*
import org.junit.Test

class NetworkTransportTest {
    @Test fun activeVpnTransportWinsOverOtherValidatedNetworks() {
        // On the phone, Android kept validated mobile data while the VPN
        // moved to Wi-Fi whose physical validation probe had not passed.
        val available = listOf(NetworkTransport("Mobile data", true), NetworkTransport("Wi-Fi", false))
        assertEquals("Wi-Fi", currentNetworkTransport("Wi-Fi", available))
        assertEquals("Mobile data", currentNetworkTransport("Mobile data", available.reversed()))
    }

    @Test fun unknownActiveTransportFallsBackToValidatedPhysicalNetwork() {
        assertEquals("Mobile data", currentNetworkTransport(null,
            listOf(NetworkTransport("Wi-Fi", false), NetworkTransport("Mobile data", true))))
        assertEquals("Wi-Fi", currentNetworkTransport(null, listOf(NetworkTransport("Wi-Fi", false))))
    }

    @Test fun noNetworkHasNoTransportLabel() {
        assertNull(currentNetworkTransport(null, emptyList()))
    }
}
