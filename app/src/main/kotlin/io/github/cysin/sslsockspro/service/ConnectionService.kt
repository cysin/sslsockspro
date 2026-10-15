package io.github.cysin.sslsockspro.service

import android.app.Notification
import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.LinkProperties
import android.net.VpnService
import android.os.Binder
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.os.Process
import io.github.cysin.sslsockspro.R
import io.github.cysin.sslsockspro.TunnelApplication
import io.github.cysin.sslsockspro.config.Endpoint
import io.github.cysin.sslsockspro.config.StunnelDocument
import io.github.cysin.sslsockspro.data.Credentials
import io.github.cysin.sslsockspro.data.OpenVpnDocument
import io.github.cysin.sslsockspro.engine.EngineService
import io.github.cysin.sslsockspro.engine.IEngineCallback
import io.github.cysin.sslsockspro.engine.IEngineService
import io.github.cysin.sslsockspro.model.ConnectionMode
import io.github.cysin.sslsockspro.model.ConnectionStage
import io.github.cysin.sslsockspro.model.ConnectionStatus
import io.github.cysin.sslsockspro.model.TunnelProfile
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.net.InetAddress
import java.util.UUID

/** The TUN owner contains no third-party native code. Native engine failure
 * leaves the interface open and blocking until recovery or an explicit stop.
 */
class ConnectionService : VpnService() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val manager by lazy { getSystemService(ConnectivityManager::class.java) }
    private val store get() = (application as TunnelApplication).profiles
    @Volatile private var profile: TunnelProfile? = null
    @Volatile private var session = ""
    private var engine: IEngineService? = null
    @Volatile private var tun: ParcelFileDescriptor? = null
    private var bound = false
    @Volatile private var intentionalStop = false
    @Volatile private var underlying: Network? = null
    private var reconnectJob: Job? = null
    private var startJob: Job? = null
    private var stopJob: Job? = null
    private var gateways = "{}"
    private var retry = 0
    private var registered = false
    private var networkSignature = 0
    private var reconnectEnabled = true
    private var permanentFailure = false
    private val localBinder = object : Binder() { }
    private val callback = object : IEngineCallback.Stub() {
        override fun protectSocket(socket: ParcelFileDescriptor, sessionId: String): Boolean {
            return socket.use {
                if (sessionId != session || Binder.getCallingUid() != Process.myUid() || intentionalStop) return@use false
                try {
                    if (profile?.mode != ConnectionMode.LOCAL_PROXY && !protect(it.fd)) return@use false
                    underlying?.bindSocket(it.fileDescriptor)
                    true
                } catch (_: Exception) { false }
            }
        }
        override fun acquireTun(networkConfiguration: String, sessionId: String): ParcelFileDescriptor? {
            if (Binder.getCallingUid() != Process.myUid()) return null
            synchronized(this@ConnectionService) {
                if (sessionId != session || intentionalStop) return null
                if (profile?.mode == ConnectionMode.OPENVPN) {
                    val configuration = JSONObject(networkConfiguration)
                    val address = configuration.optString("ipv4")
                    try {
                        if (address.isNotBlank() || configuration.optString("ipv6").isNotBlank()) establish(configuration)
                    } catch (failure: IllegalArgumentException) {
                        scope.launch {
                            if (sessionId == session && !intentionalStop) {
                                permanentFailure = true
                                failed(failure.message ?: "OpenVPN network configuration is invalid", retryAllowed = false)
                            }
                        }
                        return null
                    }
                }
                return tun?.let { ParcelFileDescriptor.dup(it.fileDescriptor) }
            }
        }
        override fun status(stage: String, message: String, sessionId: String) {
            if (sessionId != session) return
            scope.launch {
                if (sessionId != session || intentionalStop) return@launch
                if (stage == "LOG") { TunnelState.log(message); return@launch }
                // Keep the first actionable configuration/authentication
                // error. Native shutdown can emit generic errors afterward.
                if (permanentFailure) return@launch
                val permanent = stage in setOf("AUTH_ERROR", "CONFIG_ERROR")
                val value = runCatching { ConnectionStage.valueOf(stage) }.getOrDefault(ConnectionStage.ERROR)
                if (value == ConnectionStage.ERROR) { if (permanent) permanentFailure = true; failed(message, retryAllowed = !permanent) }
                else {
                    if (value in setOf(ConnectionStage.CONNECTED, ConnectionStage.LISTENING)) retry = 0
                    state(value, message)
                }
            }
        }
        override fun traffic(received: Long, sent: Long, sessionId: String) {
            if (sessionId != session) return
            scope.launch {
                if (sessionId == session) TunnelState.status(TunnelState.status.value.copy(bytesReceived = received, bytesSent = sent))
            }
        }
    }
    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName, service: IBinder) {
            engine = IEngineService.Stub.asInterface(service)
            if (!intentionalStop && profile != null && TunnelState.status.value.stage == ConnectionStage.CONNECTING) launchEngine()
        }
        override fun onServiceDisconnected(name: ComponentName) { engine = null; if (!intentionalStop) failed("Native worker stopped. Traffic remains blocked while reconnecting.") }
        override fun onBindingDied(name: ComponentName) {
            engine = null
            if (bound) { runCatching { unbindService(this) }; bound = false }
            if (!intentionalStop) failed("Native worker exited. Reconnecting without direct fallback.")
        }
    }
    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) { networkChanged() }
        override fun onLost(network: Network) { networkChanged() }
        override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) { networkChanged() }
        override fun onLinkPropertiesChanged(network: Network, properties: LinkProperties) { networkChanged() }
    }

    override fun onBind(intent: Intent): IBinder? = if (intent.action == SERVICE_INTERFACE) super.onBind(intent) else localBinder

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == STOP) {
            if (isAlwaysOn) { state(ConnectionStage.ERROR, "Always-on VPN is controlled by Android VPN settings."); return START_STICKY }
            disconnect(); return START_NOT_STICKY
        }
        if (stopJob?.isActive == true) return START_NOT_STICKY
        startForeground(1, notification("Preparing connection"), ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        if (!registered) {
            manager.registerNetworkCallback(NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(), networkCallback)
            registered = true
        }
        startJob?.cancel()
        val requestedId = intent?.getStringExtra(PROFILE)
        startJob = scope.launch {
            try {
                val settings = withContext(Dispatchers.IO) {
                    val settings = store.read().settings
                    if (requestedId != null) store.settings(settings.copy(selectedProfileId = requestedId))
                    settings
                }
                reconnectEnabled = settings.reconnect
                val id = requestedId ?: settings.selectedProfileId
                require(id != null) { "Import and select a profile first." }
                connect(id)
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (failure: Exception) {
                state(ConnectionStage.ERROR, failure.message ?: "Could not open encrypted profiles")
                stopIfUnprotected()
            }
        }
        return START_STICKY
    }

    private suspend fun connect(id: String) {
        intentionalStop = false
        permanentFailure = false
        reconnectJob?.cancel()
        runCatching { engine?.stop(session) }
        session = UUID.randomUUID().toString()
        val requestSession = session
        try {
            val selected = withContext(Dispatchers.IO) { store.read().profiles.firstOrNull { it.id == id } ?: error("Profile no longer exists") }
            if (requestSession != session) return
            if (profile?.id != selected.id) TunnelState.status(ConnectionStatus(profileId = selected.id))
            profile = selected
            state(ConnectionStage.VALIDATING, "Checking configuration and credentials")
            withContext(Dispatchers.IO) { Credentials.validate(selected) }
            if (selected.mode == ConnectionMode.LOCAL_PROXY) {
                check(!isAlwaysOn) { "Turn off Android always-on VPN before using local proxy mode" }
                synchronized(this) { tun?.close(); tun = null }
            }
            underlying = physicalNetwork() ?: error("No Wi-Fi or mobile network is available")
            networkSignature = signature(underlying)
            val capabilities = manager.getNetworkCapabilities(underlying!!)
            check(capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL) != true) {
                "This hotspot needs sign-in. Open Wi-Fi settings, sign in, and reconnect."
            }
            if (selected.mode == ConnectionMode.PROXY_VPN) check(manager.getLinkProperties(underlying!!)?.privateDnsServerName.isNullOrBlank()) {
                "Android Private DNS is set to a strict provider. Choose Automatic or Off in Android Private DNS settings to use the VPN's encrypted DNS. No DNS was sent directly."
            }
            setUnderlyingNetworks(arrayOf(underlying!!))
            gateways = withContext(Dispatchers.IO) { resolveGateways(selected, underlying!!) }
            if (selected.mode != ConnectionMode.LOCAL_PROXY && prepare(this) != null) error("Approve the Android VPN permission before connecting")
            if (selected.mode == ConnectionMode.PROXY_VPN) establish(JSONObject())
            if (selected.mode == ConnectionMode.OPENVPN && tun == null) establish(JSONObject())
            state(ConnectionStage.CONNECTING, if (selected.mode == ConnectionMode.LOCAL_PROXY) "Starting local TLS listeners" else "Traffic blocked until the tunnel is ready")
            if (engine == null && !bound) {
                bound = bindService(Intent(this, EngineService::class.java), connection, Context.BIND_AUTO_CREATE)
                check(bound) { "Could not start native engine worker" }
            } else launchEngine()
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

    @Synchronized private fun establish(configuration: JSONObject) {
        val selected = profile ?: return
        val builder = Builder().setSession(selected.name).setMtu(configuration.optInt("mtu", 1500).coerceIn(1280, 9000))
            .setBlocking(false)
        val assigned = selected.mode == ConnectionMode.OPENVPN &&
            (configuration.optString("ipv4").isNotBlank() || configuration.optString("ipv6").isNotBlank())
        val ipv4 = if (assigned) configuration.optString("ipv4") else "198.18.0.1"
        val ipv6 = if (assigned) configuration.optString("ipv6")
            else if (selected.mode == ConnectionMode.PROXY_VPN && selected.proxyIpv6) "fd00:5353::1/126" else ""
        if (ipv4.isNotBlank()) builder.addAddress(ipv4, configuration.optInt("prefix", 30).coerceIn(0, 32)).addRoute("0.0.0.0", 0)
        if (ipv6.isNotBlank()) builder.addAddress(ipv6.substringBefore('/'), ipv6.substringAfter('/', "126").toInt().coerceIn(0, 128)).addRoute("::", 0)
        // Never call allowFamily or excludeRoute: an omitted family is blocked
        // by Android rather than falling through to the physical network.
        val dns = configuration.optJSONArray("dns")
        if (assigned) {
            val servers = if (dns == null) emptyList() else (0 until dns.length()).map(dns::getString).filter {
                if (it.contains(':')) ipv6.isNotBlank() else ipv4.isNotBlank()
            }
            require(servers.isNotEmpty()) { "OpenVPN needs a DNS server in an assigned address family. Configure dhcp-option DNS or server-pushed DNS." }
            servers.forEach { builder.addDnsServer(it) }
        } else builder.addDnsServer("198.18.0.2")
        selected.includedApps.forEach { builder.addAllowedApplication(it) }
        val replacement = builder.establish() ?: error("Android revoked VPN permission")
        val previous = tun
        tun = replacement
        previous?.close()
    }

    private fun launchEngine() {
        val selected = profile ?: return
        val current = session
        val resolved = gateways
        val worker = engine ?: return
        scope.launch(Dispatchers.IO) {
            try { if (current == session && !intentionalStop) worker.start(selected.id, current, resolved, callback) }
            catch (failure: Exception) { scope.launch(Dispatchers.Main) { if (current == session) failed("Could not communicate with native worker") } }
        }
    }

    private fun failed(message: String, retryAllowed: Boolean = true) {
        if (intentionalStop) return
        if (permanentFailure && retryAllowed) return
        state(ConnectionStage.ERROR, message)
        if (!retryAllowed) { reconnectJob?.cancel(); reconnectJob = null }
        if (!retryAllowed || profile == null || reconnectJob?.isActive == true) return
        reconnectJob = scope.launch {
            reconnectEnabled = withContext(Dispatchers.IO) { runCatching { store.read().settings.reconnect }.getOrDefault(false) }
            if (!reconnectEnabled || intentionalStop) { reconnectJob = null; return@launch }
            val delaySeconds = (1L shl retry.coerceAtMost(5)).coerceAtMost(30)
            retry++
            state(ConnectionStage.RECONNECTING, "$message Retrying in $delaySeconds seconds.")
            delay(delaySeconds * 1000)
            reconnectJob = null
            if (withContext(Dispatchers.IO) { runCatching { store.read().settings.reconnect }.getOrDefault(false) } && !intentionalStop)
                profile?.id?.let { connect(it) }
        }
    }

    private fun networkChanged() {
        scope.launch {
            val replacement = physicalNetwork()
            val changed = signature(replacement)
            if ((replacement != underlying || changed != networkSignature) && profile != null && !intentionalStop) {
                underlying = replacement
                networkSignature = changed
                if (replacement == null) failed("Network unavailable; protected traffic remains blocked.")
                else failed("Network changed; rebuilding the encrypted connection.")
            }
        }
    }

    private fun signature(network: Network?): Int = if (network == null) 0 else listOf(
        manager.getNetworkCapabilities(network)?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED),
        manager.getNetworkCapabilities(network)?.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL),
        manager.getLinkProperties(network)).hashCode()

    private fun physicalNetwork(): Network? = manager.allNetworks.filter {
        manager.getNetworkCapabilities(it)?.let { caps ->
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED) &&
                !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
        } == true
    }.sortedWith(compareByDescending<Network> {
        manager.getNetworkCapabilities(it)?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true
    }.thenByDescending {
        manager.getNetworkCapabilities(it)?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED) == true
    }.thenByDescending {
        manager.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
    }).firstOrNull()

    private fun resolveGateways(selected: TunnelProfile, network: Network): String {
        val endpoints = mutableListOf<Endpoint>()
        if (selected.mode != ConnectionMode.OPENVPN || selected.openVpnViaStunnel) {
            val document = StunnelDocument.parse(selected.config)
            document.sections.forEach { endpoints += document.remotes(it) }
        }
        if (selected.mode == ConnectionMode.OPENVPN && !selected.openVpnViaStunnel) {
            endpoints += OpenVpnDocument.remotes(selected.openVpnConfig)
        }
        require(endpoints.isNotEmpty()) { "Profile has no gateway endpoint" }
        val result = JSONObject()
        endpoints.map { it.host }.distinct().forEach { host ->
            val addresses = network.getAllByName(host)
            require(addresses.isNotEmpty()) { "Gateway hostname could not be resolved" }
            result.put(host, addresses.first().hostAddress!!.substringBefore('%'))
        }
        result.put("allowed", JSONArray(endpoints.map { "${result.getString(it.host)}|${it.port}" }.distinct()))
        return result.toString()
    }

    private fun state(stage: ConnectionStage, message: String) {
        val old = TunnelState.status.value
        TunnelState.status(old.copy(stage = stage, profileId = profile?.id, message = message,
            running = profile != null, vpnActive = tun != null, alwaysOn = isAlwaysOn,
            startedAt = if (old.startedAt == 0L && stage in setOf(ConnectionStage.CONNECTED, ConnectionStage.LISTENING)) System.currentTimeMillis() else old.startedAt))
        TunnelState.log(message)
        getSystemService(android.app.NotificationManager::class.java).notify(1, notification(message))
    }

    private fun notification(message: String): Notification {
        val open = PendingIntent.getActivity(this, 0, Intent(this, io.github.cysin.sslsockspro.ui.MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val stop = PendingIntent.getService(this, 1, Intent(this, ConnectionService::class.java).setAction(STOP), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        return Notification.Builder(this, "tunnel").setSmallIcon(R.drawable.ic_tunnel).setContentTitle("SSLSocks Pro")
            .setContentText(message.take(160)).setContentIntent(open).setOngoing(true)
            .apply { if (!isAlwaysOn) addAction(Notification.Action.Builder(null, "Disconnect", stop).build()) }.build()
    }

    private fun disconnect() {
        if (stopJob?.isActive == true) return
        intentionalStop = true
        startJob?.cancel(); reconnectJob?.cancel()
        val stoppedSession = session
        state(ConnectionStage.STOPPING, "Stopping connection")
        stopJob = scope.launch {
            val worker = engine
            val stopped = withContext(Dispatchers.IO) {
                worker == null || runCatching { worker.stopAndWait(stoppedSession) }.getOrDefault(false)
            }
            if (!stopped && engine != null) {
                state(ConnectionStage.ERROR, "Native worker has not confirmed shutdown. Traffic remains blocked; retry Disconnect.")
                return@launch
            }
            if (bound) { runCatching { unbindService(connection) }; bound = false }
            engine = null
            synchronized(this@ConnectionService) { tun?.close(); tun = null }
            session = ""
            profile = null
            TunnelState.status(ConnectionStatus())
            stopForeground(STOP_FOREGROUND_REMOVE); stopSelf()
        }
    }

    private fun stopIfUnprotected() {
        if (tun != null) return
        intentionalStop = true
        profile = null
        val old = TunnelState.status.value
        TunnelState.status(old.copy(running = false, vpnActive = false, alwaysOn = isAlwaysOn))
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onRevoke() { scope.launch { disconnect() }; super.onRevoke() }
    override fun onDestroy() {
        intentionalStop = true
        runCatching { engine?.stop(session) }
        if (bound) runCatching { unbindService(connection) }
        runCatching { tun?.close() }
        if (registered) runCatching { manager.unregisterNetworkCallback(networkCallback) }
        val old = TunnelState.status.value
        TunnelState.status(old.copy(running = false, vpnActive = false, alwaysOn = false))
        scope.cancel(); super.onDestroy()
    }

    companion object {
        const val STOP = "io.github.cysin.sslsockspro.STOP"
        const val PROFILE = "profile"
        fun start(context: Context, profile: TunnelProfile) = context.startForegroundService(Intent(context, ConnectionService::class.java).putExtra(PROFILE, profile.id))
        fun stop(context: Context) = context.startService(Intent(context, ConnectionService::class.java).setAction(STOP))
    }
}
