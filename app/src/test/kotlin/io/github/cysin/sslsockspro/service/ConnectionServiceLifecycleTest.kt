package io.github.cysin.sslsockspro.service

import io.github.cysin.sslsockspro.model.ConnectionStage
import io.github.cysin.sslsockspro.model.ConnectionStatus
import org.junit.After
import org.junit.Assert.*
import org.junit.Test

class ConnectionServiceLifecycleTest {
    @After fun clearStatus() { TunnelState.status(ConnectionStatus()) }

    @Test fun destroyedStoppingOwnerReturnsToIdle() {
        val service = ConnectionService()
        TunnelState.status(ConnectionStatus(stage = ConnectionStage.STOPPING,
            profileId = "test-profile", message = "Stopping connection",
            running = true, vpnActive = true, alwaysOn = true))

        service.onDestroy()

        assertEquals(ConnectionStatus(), TunnelState.status.value)
    }

    @Test fun revocationClearsAnExistingConnectionError() {
        val service = ConnectionService()
        TunnelState.status(ConnectionStatus(stage = ConnectionStage.ERROR,
            message = "Worker stopped; protected traffic is blocked",
            running = true, vpnActive = true))

        service.onRevoke()
        service.onDestroy()

        assertEquals(ConnectionStatus(), TunnelState.status.value)
    }

    @Test fun validationErrorRemainsVisibleAfterUnprotectedOwnerStops() {
        val service = ConnectionService()
        TunnelState.status(ConnectionStatus(stage = ConnectionStage.ERROR,
            message = "Client certificate has expired", running = true))

        service.onDestroy()

        val status = TunnelState.status.value
        assertEquals(ConnectionStage.ERROR, status.stage)
        assertEquals("Client certificate has expired", status.message)
        assertFalse(status.running)
        assertFalse(status.vpnActive)
        assertFalse(status.alwaysOn)
    }

    @Test fun missingSelectedAppsAreSkippedButNeverWidenToAllApps() {
        assertEquals(listOf("org.example.kept"),
            ConnectionService.routedApplications(listOf("org.example.kept", "org.example.removed")) { it == "org.example.kept" })
        assertEquals(emptyList<String>(), ConnectionService.routedApplications(emptyList()) { false })
        assertThrows(IllegalArgumentException::class.java) {
            ConnectionService.routedApplications(listOf("org.example.removed")) { false }
        }
    }
}
