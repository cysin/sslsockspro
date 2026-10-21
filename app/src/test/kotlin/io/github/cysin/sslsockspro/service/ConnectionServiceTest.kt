package io.github.cysin.sslsockspro.service

import org.junit.Assert.*
import org.junit.Test

/** Lifecycle transitions are covered by TunnelControllerTest. */
class ConnectionServiceTest {
    @Test fun missingSelectedAppsAreSkippedButNeverWidenToAllApps() {
        assertEquals(listOf("org.example.kept"),
            ConnectionService.routedApplications(listOf("org.example.kept", "org.example.removed")) { it == "org.example.kept" })
        assertEquals(emptyList<String>(), ConnectionService.routedApplications(emptyList()) { false })
        assertThrows(IllegalArgumentException::class.java) {
            ConnectionService.routedApplications(listOf("org.example.removed")) { false }
        }
    }
}
