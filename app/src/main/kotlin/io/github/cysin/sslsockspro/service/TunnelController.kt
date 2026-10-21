package io.github.cysin.sslsockspro.service

import io.github.cysin.sslsockspro.config.GatewayPlan
import io.github.cysin.sslsockspro.engine.EngineEvent
import io.github.cysin.sslsockspro.model.ConnectionMode
import io.github.cysin.sslsockspro.model.ConnectionStage
import io.github.cysin.sslsockspro.model.ConnectionStatus
import io.github.cysin.sslsockspro.model.TunnelProfile
import io.github.cysin.sslsockspro.privacy.Redactor
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.util.UUID

/** Connection lifecycle of the VPN owner. Every method runs on the owner's
 * single (main) thread; Binder threads only read [profile] and [accepts].
 *
 * Invariants: worker or network failure keeps the blocking TUN open; only an
 * explicit disconnect, VPN revocation, service destruction, or local-proxy
 * mode closes it. Configuration and authentication errors stop retrying and
 * the first actionable error stays visible. */
class TunnelController(private val platform: TunnelPlatform, private val scope: CoroutineScope) {
    companion object { const val NETWORK_SETTLE_MILLIS = 2000L }

    @Volatile var profile: TunnelProfile? = null
        private set
    @Volatile var session = ""
        private set
    @Volatile private var intentionalStop = false
    private var permissionRevoked = false
    private var permanentFailure = false
    private var reconnectEnabled = true
    private var retry = 0
    private var network: NetworkSnapshot? = null
    private var gateways: GatewayPlan? = null
    private var startJob: Job? = null
    private var reconnectJob: Job? = null
    private var stopJob: Job? = null
    private var networkJob: Job? = null

    val stopping: Boolean get() = stopJob?.isActive == true

    /** Binder-side check that a worker request belongs to the live session. */
    fun accepts(sessionId: String): Boolean = sessionId == session && !intentionalStop

    fun start(requestedProfileId: String?) {
        if (stopping) return
        startJob?.cancel()
        startJob = scope.launch {
            try {
                val settings = platform.settings()
                if (requestedProfileId != null) platform.select(requestedProfileId)
                reconnectEnabled = settings.reconnect
                val id = requestedProfileId ?: settings.selectedProfileId
                require(id != null) { "Import and select a profile first." }
                connect(id)
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (failure: Exception) {
                state(ConnectionStage.ERROR, failure.message ?: "Could not open encrypted profiles")
                stopIfUnprotected()
            }
        }
    }

    /** Returns false when Android's always-on VPN owns the decision. */
    fun stop(): Boolean {
        if (platform.alwaysOn) {
            state(ConnectionStage.ERROR, "Always-on VPN is controlled by Android VPN settings.")
            return false
        }
        disconnect()
        return true
    }

    private suspend fun connect(id: String) {
        intentionalStop = false
        permanentFailure = false
        reconnectJob?.cancel()
        if (session.isNotEmpty()) platform.stopEngine(session)
        session = UUID.randomUUID().toString()
        val requestSession = session
        try {
            val selected = platform.profile(id) ?: error("Profile no longer exists")
            if (requestSession != session) return
            if (profile?.id != selected.id) platform.status = ConnectionStatus(profileId = selected.id)
            profile = selected
            state(ConnectionStage.VALIDATING, "Checking configuration and credentials")
            platform.validate(selected)
            if (selected.mode == ConnectionMode.LOCAL_PROXY) {
                check(!platform.alwaysOn) { "Turn off Android always-on VPN before using local proxy mode" }
                platform.closeTun()
            }
            val current = platform.physicalNetwork() ?: error("No Wi-Fi or mobile network is available")
            network = current
            platform.bindSocketsTo(current)
            check(!current.captivePortal) { "This hotspot needs sign-in. Open Wi-Fi settings, sign in, and reconnect." }
            if (selected.mode == ConnectionMode.PROXY_VPN) check(!current.strictPrivateDns) {
                "Android Private DNS is set to a strict provider. Choose Automatic or Off in Android Private DNS settings to use the VPN's encrypted DNS. No DNS was sent directly."
            }
            platform.advertise(current)
            gateways = platform.resolveGateways(selected, current)
            if (selected.mode != ConnectionMode.LOCAL_PROXY && platform.vpnPermissionMissing()) error("Approve the Android VPN permission before connecting")
            if (selected.mode == ConnectionMode.PROXY_VPN) platform.establishBlocking(selected)
            if (selected.mode == ConnectionMode.OPENVPN && !platform.tunOpen) platform.establishBlocking(selected)
            state(ConnectionStage.CONNECTING, if (selected.mode == ConnectionMode.LOCAL_PROXY) "Starting local TLS listeners" else "Traffic blocked until the tunnel is ready")
            if (!platform.engineReady && !platform.engineBound) check(platform.bindEngine()) { "Could not start native engine worker" }
            else launchEngine()
        } catch (cancelled: CancellationException) { throw cancelled }
        catch (failure: Exception) {
            if (requestSession == session) {
                state(ConnectionStage.ERROR, failure.message ?: "Connection validation failed")
                // Configuration/authentication errors require an edit, not an
                // endless decrypt/validate/retry loop on the phone.
                stopIfUnprotected()
            }
        }
    }

    private fun launchEngine() {
        val selected = profile ?: return
        val plan = gateways ?: return
        if (!platform.engineReady || intentionalStop) return
        platform.startEngine(selected, session, plan)
    }

    fun engineConnected() {
        if (!intentionalStop && profile != null && platform.status.stage == ConnectionStage.CONNECTING) launchEngine()
    }

    fun engineDisconnected() {
        if (!intentionalStop) failed("Native worker stopped. Traffic remains blocked while reconnecting.")
    }

    fun engineDied() {
        if (!intentionalStop) failed("Native worker exited. Reconnecting without direct fallback.")
    }

    fun engineUnreachable(sessionId: String) {
        if (sessionId == session) failed("Could not communicate with native worker")
    }

    fun engineEvent(code: Int, detail: String, sessionId: String) {
        if (!accepts(sessionId)) return
        if (code == EngineEvent.LOG) { platform.log(detail); return }
        // Keep the first actionable configuration/authentication error.
        // Native shutdown can emit generic errors afterward.
        if (permanentFailure) return
        val message = EngineEvent.message(code, detail, profile?.mode)
        if (EngineEvent.isFailure(code)) {
            val permanent = EngineEvent.isPermanent(code)
            if (permanent) permanentFailure = true
            failed(message, retryAllowed = !permanent)
            return
        }
        val stage = when (code) {
            EngineEvent.LISTENING -> ConnectionStage.LISTENING
            EngineEvent.CONNECTED -> ConnectionStage.CONNECTED
            else -> ConnectionStage.RECONNECTING
        }
        if (stage == ConnectionStage.CONNECTED || stage == ConnectionStage.LISTENING) retry = 0
        state(stage, message)
    }

    /** The worker's OpenVPN network configuration could not be applied. */
    fun tunRejected(sessionId: String, message: String) {
        if (!accepts(sessionId)) return
        permanentFailure = true
        failed(message, retryAllowed = false)
    }

    fun traffic(received: Long, sent: Long, sessionId: String) {
        if (sessionId == session) platform.status = platform.status.copy(bytesReceived = received, bytesSent = sent)
    }

    /** Network callbacks arrive in bursts; act once they settle. */
    fun networkChanged() {
        networkJob?.cancel()
        networkJob = scope.launch { delay(NETWORK_SETTLE_MILLIS); evaluateNetwork() }
    }

    /** A working tunnel survives a network change: new gateway sockets bind
     * to the new network and the worker re-checks the tunnel, escalating to
     * a full reconnect only if that check fails. */
    private fun evaluateNetwork() {
        val replacement = platform.physicalNetwork()
        if (profile == null || intentionalStop) return
        val previous = network
        if (replacement?.key == previous?.key && replacement?.signature == previous?.signature) return
        network = replacement
        platform.bindSocketsTo(replacement)
        val established = platform.status.stage == ConnectionStage.CONNECTED || platform.status.stage == ConnectionStage.LISTENING
        when {
            replacement == null -> failed("Network unavailable; protected traffic remains blocked.")
            replacement.captivePortal -> failed("This hotspot needs sign-in. Open Wi-Fi settings, sign in, and reconnect.", retryAllowed = false)
            profile?.mode == ConnectionMode.PROXY_VPN && replacement.strictPrivateDns -> failed(
                "Android Private DNS is set to a strict provider. Choose Automatic or Off in Android Private DNS settings to use the VPN's encrypted DNS. No DNS was sent directly.",
                retryAllowed = false)
            previous == null || !established -> reconnectNow("Network available; reconnecting.")
            else -> {
                if (replacement.key != previous.key) platform.advertise(replacement)
                platform.engineNetworkChanged(session, sameNetwork = replacement.key == previous.key)
                platform.log("Network changed; keeping the tunnel and checking it")
            }
        }
    }

    /** The network is usable again: do not wait out the backoff delay. */
    private fun reconnectNow(message: String) {
        if (permanentFailure || !reconnectEnabled) { failed(message); return }
        reconnectJob?.cancel()
        retry = 0
        state(ConnectionStage.RECONNECTING, message)
        val id = profile?.id ?: return
        reconnectJob = scope.launch { reconnectJob = null; connect(id) }
    }

    private fun failed(message: String, retryAllowed: Boolean = true) {
        if (intentionalStop) return
        if (permanentFailure && retryAllowed) return
        state(ConnectionStage.ERROR, message)
        if (!retryAllowed) { reconnectJob?.cancel(); reconnectJob = null }
        if (!retryAllowed || profile == null || reconnectJob?.isActive == true) return
        reconnectJob = scope.launch {
            // The setting read at connection start decides whether to wait;
            // it is reread once afterward so a change during the wait counts.
            if (!reconnectEnabled || intentionalStop) { reconnectJob = null; return@launch }
            val delaySeconds = (1L shl retry.coerceAtMost(5)).coerceAtMost(30)
            retry++
            state(ConnectionStage.RECONNECTING, "$message Retrying in $delaySeconds seconds.")
            delay(delaySeconds * 1000)
            reconnectJob = null
            reconnectEnabled = try { platform.settings().reconnect }
                catch (cancelled: CancellationException) { throw cancelled }
                catch (_: Exception) { false }
            if (reconnectEnabled && !intentionalStop) profile?.id?.let { connect(it) }
        }
    }

    private fun disconnect() {
        if (stopping) return
        intentionalStop = true
        startJob?.cancel(); reconnectJob?.cancel()
        val stoppedSession = session
        state(ConnectionStage.STOPPING, "Stopping connection")
        stopJob = scope.launch {
            if (!platform.stopEngineAndWait(stoppedSession) && platform.engineReady) {
                state(ConnectionStage.ERROR, "Native worker has not confirmed shutdown. Traffic remains blocked; retry Disconnect.")
                return@launch
            }
            platform.unbindEngine()
            platform.closeTun()
            session = ""
            profile = null
            platform.status = ConnectionStatus()
            platform.stopService()
        }
    }

    private fun stopIfUnprotected() {
        if (platform.tunOpen) return
        intentionalStop = true
        profile = null
        platform.status = platform.status.copy(running = false, vpnActive = false, alwaysOn = platform.alwaysOn)
        platform.stopService()
    }

    /** Android has already deactivated this VPN and will stop the service;
     * an asynchronous disconnect would be cancelled by that teardown. */
    fun revoked() {
        permissionRevoked = true
        intentionalStop = true
    }

    fun destroyed() {
        intentionalStop = true
        networkJob?.cancel()
        platform.stopEngine(session)
        platform.unbindEngine()
        platform.closeTun()
        val old = platform.status
        // A destroyed owner cannot still be connecting/stopping. Keep an
        // actionable validation error unless the user explicitly revoked VPN.
        platform.status = if (old.stage == ConnectionStage.ERROR && !permissionRevoked)
            old.copy(running = false, vpnActive = false, alwaysOn = false) else ConnectionStatus()
    }

    private fun state(stage: ConnectionStage, detail: String) {
        val message = Redactor.redactIdentifiers(detail)
        val old = platform.status
        platform.status = old.copy(stage = stage, profileId = profile?.id, message = message,
            running = profile != null, vpnActive = platform.tunOpen, alwaysOn = platform.alwaysOn,
            startedAt = if (old.startedAt == 0L && (stage == ConnectionStage.CONNECTED || stage == ConnectionStage.LISTENING)) platform.now() else old.startedAt)
        platform.log(message)
        platform.notify(message)
    }
}
