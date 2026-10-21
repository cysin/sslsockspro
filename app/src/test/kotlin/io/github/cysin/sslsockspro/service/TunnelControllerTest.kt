package io.github.cysin.sslsockspro.service

import io.github.cysin.sslsockspro.config.GatewayPlan
import io.github.cysin.sslsockspro.engine.EngineEvent
import io.github.cysin.sslsockspro.model.AppSettings
import io.github.cysin.sslsockspro.model.ConnectionMode
import io.github.cysin.sslsockspro.model.ConnectionStage
import io.github.cysin.sslsockspro.model.ConnectionStatus
import io.github.cysin.sslsockspro.model.TunnelProfile
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import org.junit.Assert.*
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class TunnelControllerTest {
    private class FakePlatform(var profileValue: TunnelProfile?) : TunnelPlatform {
        override var alwaysOn = false
        override var tunOpen = false
        override var engineBound = false
        override var engineReady = false
        override var status = ConnectionStatus()
        var settingsValue = AppSettings(selectedProfileId = profileValue?.id)
        var validation: Exception? = null
        var network: NetworkSnapshot? = NetworkSnapshot("wifi", 1)
        var stopConfirmed = true
        val started = mutableListOf<String>()
        val stoppedSessions = mutableListOf<String>()
        val events = mutableListOf<String>()
        var serviceStopped = false

        override fun now() = 42L
        override fun vpnPermissionMissing() = false
        override suspend fun settings() = settingsValue
        override suspend fun select(profileId: String) { settingsValue = settingsValue.copy(selectedProfileId = profileId) }
        override suspend fun profile(id: String) = profileValue?.takeIf { it.id == id }
        override suspend fun validate(profile: TunnelProfile) { validation?.let { throw it } }
        override fun physicalNetwork() = network
        override fun bindSocketsTo(network: NetworkSnapshot?) { events += "bind:${network?.key}" }
        override fun advertise(network: NetworkSnapshot) { events += "advertise:${network.key}" }
        override suspend fun resolveGateways(profile: TunnelProfile, network: NetworkSnapshot) =
            GatewayPlan(mapOf("192.0.2.1" to listOf("192.0.2.1")), listOf("192.0.2.1|9983"))
        override fun establishBlocking(profile: TunnelProfile) { tunOpen = true; events += "establish" }
        override fun closeTun() { tunOpen = false; events += "closeTun" }
        override fun bindEngine(): Boolean { engineBound = true; return true }
        override fun startEngine(profile: TunnelProfile, session: String, gateways: GatewayPlan) { started += session }
        override fun stopEngine(session: String) { stoppedSessions += session }
        override suspend fun stopEngineAndWait(session: String) = stopConfirmed
        override fun unbindEngine() { engineBound = false; engineReady = false; events += "unbind" }
        override fun engineNetworkChanged(session: String, sameNetwork: Boolean) { events += "networkChanged:$sameNetwork" }
        override fun log(message: String) { }
        var notice: String? = null
        override fun notice(message: String?) { notice = message }
        var challenge: String? = null
        override fun challenge(prompt: String?) { challenge = prompt }
        override fun notify(message: String) { }
        override fun stopService() { serviceStopped = true }
    }

    private val vpnProfile = TunnelProfile(name = "vpn", config = "", mode = ConnectionMode.PROXY_VPN)
    private val scope = TestScope()
    private val platform = FakePlatform(vpnProfile)
    private val controller = TunnelController(platform, scope)

    private fun connected(): String {
        controller.start(null)
        scope.runCurrent()
        assertEquals(ConnectionStage.CONNECTING, platform.status.stage)
        platform.engineReady = true
        controller.engineConnected()
        val session = platform.started.single()
        controller.engineEvent(EngineEvent.CONNECTED, "", session)
        assertEquals(ConnectionStage.CONNECTED, platform.status.stage)
        return session
    }

    @Test fun connectEstablishesABlockingTunBeforeStartingTheEngine() {
        val session = connected()
        assertTrue(platform.tunOpen && platform.status.vpnActive && platform.status.running)
        assertEquals(listOf("bind:wifi", "advertise:wifi", "establish"), platform.events)
        assertEquals("VPN connected: TCP and DNS tunneled; other UDP blocked", platform.status.message)
        assertEquals(42L, platform.status.startedAt)
        assertTrue(controller.accepts(session))
    }

    @Test fun workerDeathKeepsTheBlockingTunAndReconnectsWithANewSession() {
        val first = connected()
        controller.engineDisconnected()
        scope.runCurrent()
        assertEquals(ConnectionStage.RECONNECTING, platform.status.stage)
        assertTrue("Traffic must stay blocked while the worker is down", platform.tunOpen)
        assertFalse("closeTun" in platform.events)
        platform.engineReady = true
        scope.advanceTimeBy(1_001)
        scope.runCurrent()
        assertEquals(2, platform.started.size)
        assertNotEquals(first, platform.started.last())
        assertFalse(controller.accepts(first))
    }

    @Test fun permanentErrorsStopRetryingAndKeepTheFirstMessage() {
        val session = connected()
        controller.engineEvent(EngineEvent.CONFIG_ERROR, "stunnel rejected the configuration", session)
        controller.engineEvent(EngineEvent.ENGINE_STOPPED, "", session)
        scope.advanceTimeBy(60_000)
        assertEquals(ConnectionStage.ERROR, platform.status.stage)
        assertEquals("stunnel rejected the configuration", platform.status.message)
        assertEquals(1, platform.started.size)
        assertTrue(platform.tunOpen)
    }

    @Test fun disconnectReleasesTheTunOnlyAfterTheWorkerConfirms() {
        connected()
        platform.stopConfirmed = false
        assertTrue(controller.stop())
        scope.runCurrent()
        assertEquals(ConnectionStage.ERROR, platform.status.stage)
        assertTrue("An unconfirmed shutdown keeps traffic blocked", platform.tunOpen)
        assertFalse(platform.serviceStopped)
        platform.stopConfirmed = true
        assertTrue(controller.stop())
        scope.runCurrent()
        assertEquals(ConnectionStatus(), platform.status)
        assertFalse(platform.tunOpen)
        assertTrue(platform.serviceStopped)
    }

    @Test fun alwaysOnRefusesAppInitiatedDisconnect() {
        connected()
        platform.alwaysOn = true
        assertFalse(controller.stop())
        assertEquals("Always-on VPN is controlled by Android VPN settings.", platform.status.message)
        assertTrue(platform.tunOpen)
    }

    @Test fun revocationAndDestructionResetToIdleAndIgnoreLaterEvents() {
        val session = connected()
        controller.engineDisconnected()
        controller.revoked()
        controller.destroyed()
        assertEquals(ConnectionStatus(), platform.status)
        assertFalse(platform.tunOpen)
        controller.engineEvent(EngineEvent.CONNECTED, "", session)
        assertEquals(ConnectionStatus(), platform.status)
    }

    @Test fun validationErrorsStopAnUnprotectedOwnerButStayVisible() {
        platform.validation = IllegalArgumentException("Client certificate has expired")
        controller.start(null)
        scope.runCurrent()
        assertTrue(platform.serviceStopped)
        controller.destroyed()
        assertEquals(ConnectionStage.ERROR, platform.status.stage)
        assertEquals("Client certificate has expired", platform.status.message)
        assertFalse(platform.status.running || platform.status.vpnActive)
    }

    private fun settle() { scope.advanceTimeBy(TunnelController.NETWORK_SETTLE_MILLIS + 1); scope.runCurrent() }

    @Test fun lostNetworkKeepsTrafficBlockedAndRetries() {
        connected()
        platform.network = null
        controller.networkChanged()
        settle()
        assertEquals(ConnectionStage.RECONNECTING, platform.status.stage)
        assertTrue(platform.tunOpen)
        assertEquals("bind:null", platform.events.last())
    }

    @Test fun startIsIgnoredWhileStoppingAndStaleSessionsAreRejected() {
        val session = connected()
        platform.stopConfirmed = true
        controller.stop()
        assertTrue(controller.stopping)
        controller.start(null)
        assertFalse(controller.accepts(session))
        scope.runCurrent()
        assertTrue(platform.serviceStopped)
        assertEquals(1, platform.started.size)
    }

    @Test fun destroyingAStoppingOwnerReturnsToIdle() {
        connected()
        controller.stop()
        assertEquals(ConnectionStage.STOPPING, platform.status.stage)
        controller.destroyed()
        assertEquals(ConnectionStatus(), platform.status)
        assertFalse(platform.tunOpen)
    }

    @Test fun anotherNetworkKeepsTheTunnelAndAsksTheWorkerToCheckIt() {
        connected()
        platform.events.clear()
        platform.network = NetworkSnapshot("cellular", 7)
        controller.networkChanged()
        settle()
        assertEquals(listOf("bind:cellular", "advertise:cellular", "networkChanged:false"), platform.events)
        assertEquals(ConnectionStage.CONNECTED, platform.status.stage)
        assertEquals(1, platform.started.size)
    }

    @Test fun addressChangesOnTheSameNetworkAreDebounced() {
        connected()
        platform.events.clear()
        repeat(3) { index ->
            platform.network = NetworkSnapshot("wifi", 10 + index)
            controller.networkChanged()
            scope.advanceTimeBy(500)
        }
        settle()
        assertEquals(listOf("bind:wifi", "networkChanged:true"), platform.events)
    }

    @Test fun aRegainedNetworkReconnectsWithoutWaitingForBackoff() {
        connected()
        platform.network = null
        controller.networkChanged(); settle()
        assertEquals(ConnectionStage.RECONNECTING, platform.status.stage)
        // The backoff retry finds no network and stops retrying.
        scope.advanceTimeBy(60_000); scope.runCurrent()
        assertEquals(ConnectionStage.ERROR, platform.status.stage)
        assertEquals(1, platform.started.size)
        assertTrue("Traffic stays blocked without a network", platform.tunOpen)
        platform.network = NetworkSnapshot("cellular", 3)
        controller.networkChanged(); settle()
        assertEquals("Reconnected as soon as the network settled", 2, platform.started.size)
    }

    @Test fun captivePortalsWaitForSignInInsteadOfRetrying() {
        connected()
        platform.network = NetworkSnapshot("hotspot", 1, captivePortal = true)
        controller.networkChanged(); settle()
        scope.advanceTimeBy(60_000)
        assertEquals(ConnectionStage.ERROR, platform.status.stage)
        assertEquals(1, platform.started.size)
        assertTrue(platform.tunOpen)
        platform.network = NetworkSnapshot("hotspot", 2)
        controller.networkChanged(); settle()
        assertEquals("Sign-in completion reconnects", 2, platform.started.size)
    }

    @Test fun challengesAskTheUserWithoutChangingTheStage() {
        val session = connected()
        controller.engineEvent(EngineEvent.CHALLENGE, "{\"text\":\"Enter OTP\",\"echo\":true}", session)
        assertEquals(ConnectionStage.CONNECTED, platform.status.stage)
        assertEquals("{\"text\":\"Enter OTP\",\"echo\":true}", platform.challenge)
        assertEquals("OpenVPN asks for a verification code. Open SSLSocks Pro to answer it.", platform.status.message)
        controller.engineEvent(EngineEvent.NOTICE, "The server answered as SOCKS5", session)
        assertEquals("The server answered as SOCKS5", platform.notice)
        assertEquals(ConnectionStage.CONNECTED, platform.status.stage)
    }
}
