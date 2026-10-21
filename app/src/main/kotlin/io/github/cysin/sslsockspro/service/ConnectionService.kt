package io.github.cysin.sslsockspro.service

import android.app.Notification
import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Binder
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.os.Process
import io.github.cysin.sslsockspro.R
import io.github.cysin.sslsockspro.TunnelApplication
import io.github.cysin.sslsockspro.config.GatewayPlan
import io.github.cysin.sslsockspro.data.Credentials
import io.github.cysin.sslsockspro.data.Gateways
import io.github.cysin.sslsockspro.data.OpenVpnDocument
import io.github.cysin.sslsockspro.engine.EngineService
import io.github.cysin.sslsockspro.engine.IEngineCallback
import io.github.cysin.sslsockspro.engine.IEngineService
import io.github.cysin.sslsockspro.model.AppSettings
import io.github.cysin.sslsockspro.model.ConnectionMode
import io.github.cysin.sslsockspro.model.ConnectionStatus
import io.github.cysin.sslsockspro.model.TunnelProfile
import io.github.cysin.sslsockspro.privacy.Redactor
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

/** The TUN owner contains no third-party native code. Native engine failure
 * leaves the interface open and blocking until recovery or an explicit stop.
 * Lifecycle decisions live in [TunnelController]; this class performs the
 * Android operations it requests.
 */
class ConnectionService : VpnService(), TunnelPlatform {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val controller = TunnelController(this, scope)
    private val manager by lazy { getSystemService(ConnectivityManager::class.java) }
    private val store get() = (application as TunnelApplication).profiles
    private var engine: IEngineService? = null
    @Volatile private var tun: ParcelFileDescriptor? = null
    private var bound = false
    @Volatile private var underlying: Network? = null
    private var registered = false
    private val localBinder = object : Binder() { }
    private val callback = object : IEngineCallback.Stub() {
        override fun protectSocket(socket: ParcelFileDescriptor, sessionId: String): Boolean {
            return socket.use {
                if (!controller.accepts(sessionId) || Binder.getCallingUid() != Process.myUid()) return@use false
                try {
                    if (controller.profile?.mode != ConnectionMode.LOCAL_PROXY && !protect(it.fd)) return@use false
                    underlying?.bindSocket(it.fileDescriptor)
                    true
                } catch (_: Exception) { false }
            }
        }
        override fun acquireTun(networkConfiguration: String, sessionId: String): ParcelFileDescriptor? {
            if (Binder.getCallingUid() != Process.myUid()) return null
            synchronized(this@ConnectionService) {
                if (!controller.accepts(sessionId)) return null
                if (controller.profile?.mode == ConnectionMode.OPENVPN) {
                    val configuration = JSONObject(networkConfiguration)
                    try {
                        if (configuration.optString("ipv4").isNotBlank() || configuration.optString("ipv6").isNotBlank()) establish(configuration)
                    } catch (failure: IllegalArgumentException) {
                        scope.launch { controller.tunRejected(sessionId, failure.message ?: "OpenVPN network configuration is invalid") }
                        return null
                    }
                }
                return tun?.let { ParcelFileDescriptor.dup(it.fileDescriptor) }
            }
        }
        override fun event(code: Int, detail: String, sessionId: String) {
            if (sessionId == controller.session) scope.launch { controller.engineEvent(code, detail, sessionId) }
        }
        override fun traffic(received: Long, sent: Long, sessionId: String) {
            if (sessionId == controller.session) scope.launch { controller.traffic(received, sent, sessionId) }
        }
    }
    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName, service: IBinder) {
            engine = IEngineService.Stub.asInterface(service)
            controller.engineConnected()
        }
        override fun onServiceDisconnected(name: ComponentName) { engine = null; controller.engineDisconnected() }
        override fun onBindingDied(name: ComponentName) {
            engine = null
            if (bound) { runCatching { unbindService(this) }; bound = false }
            controller.engineDied()
        }
    }
    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) { networkChanged() }
        override fun onLost(network: Network) { networkChanged() }
        override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) { networkChanged() }
        override fun onLinkPropertiesChanged(network: Network, properties: LinkProperties) { networkChanged() }
    }

    private fun networkChanged() { scope.launch { controller.networkChanged() } }

    override fun onBind(intent: Intent): IBinder? = if (intent.action == SERVICE_INTERFACE) super.onBind(intent) else localBinder

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == STOP) return if (controller.stop()) START_NOT_STICKY else START_STICKY
        // startForegroundService() requires startForeground() even when this
        // request is dropped while an earlier disconnect is still finishing.
        startForeground(1, notification("Preparing connection"), ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        if (controller.stopping) return START_NOT_STICKY
        if (!registered) {
            manager.registerNetworkCallback(NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(), networkCallback)
            registered = true
        }
        controller.start(intent?.getStringExtra(PROFILE))
        return START_STICKY
    }

    override fun onRevoke() {
        controller.revoked()
        super.onRevoke()
    }

    override fun onDestroy() {
        controller.destroyed()
        if (registered) runCatching { manager.unregisterNetworkCallback(networkCallback) }
        scope.cancel(); super.onDestroy()
    }

    // TunnelPlatform

    override val alwaysOn: Boolean get() = isAlwaysOn
    override val tunOpen: Boolean get() = tun != null
    override val engineBound: Boolean get() = bound
    override val engineReady: Boolean get() = engine != null
    override var status: ConnectionStatus
        get() = TunnelState.status.value
        set(value) = TunnelState.status(value)

    override fun now(): Long = System.currentTimeMillis()
    override fun vpnPermissionMissing(): Boolean = prepare(this) != null
    override suspend fun settings(): AppSettings = withContext(Dispatchers.IO) { store.settings() }
    override suspend fun select(profileId: String) = withContext(Dispatchers.IO) {
        store.settings(store.settings().copy(selectedProfileId = profileId))
    }
    override suspend fun profile(id: String): TunnelProfile? = withContext(Dispatchers.IO) { store.profile(id) }
    override suspend fun validate(profile: TunnelProfile) = withContext(Dispatchers.IO) { Credentials.validate(profile) }

    override fun physicalNetwork(): NetworkSnapshot? {
        val network = manager.allNetworks.filter {
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
        }).firstOrNull() ?: return null
        val capabilities = manager.getNetworkCapabilities(network)
        val properties = manager.getLinkProperties(network)
        val captive = capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL) == true
        return NetworkSnapshot(network,
            listOf(capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED), captive, properties).hashCode(),
            captivePortal = captive, strictPrivateDns = !properties?.privateDnsServerName.isNullOrBlank())
    }
    override fun bindSocketsTo(network: NetworkSnapshot?) { underlying = network?.key as Network? }
    override fun advertise(network: NetworkSnapshot) { setUnderlyingNetworks(arrayOf(network.key as Network)) }
    override suspend fun resolveGateways(profile: TunnelProfile, network: NetworkSnapshot): GatewayPlan = withContext(Dispatchers.IO) {
        val endpoints = Gateways.endpoints(profile)
        GatewayPlan.create(endpoints) { host -> (network.key as Network).getAllByName(host).map { it.hostAddress!! } }
            .also { plan ->
                // OpenVPN servers reached through stunnel are named only in its logs.
                val carried = if (profile.mode == ConnectionMode.OPENVPN && profile.openVpnViaStunnel)
                    OpenVpnDocument.remotes(profile.openVpnConfig).map { it.host } else emptyList()
                Redactor.sensitiveNames(plan.hosts.keys + carried)
            }
    }

    override fun establishBlocking(profile: TunnelProfile) = establish(JSONObject())
    override fun closeTun() { synchronized(this) { tun?.close(); tun = null } }

    @Synchronized private fun establish(configuration: JSONObject) {
        val selected = controller.profile ?: return
        // A generic session name keeps profile names out of system VPN UI.
        // Unmetered VPNs inherit meteredness from the underlying network.
        val builder = Builder().setSession("SSLSocks Pro").setMtu(configuration.optInt("mtu", 1500).coerceIn(1280, 9000))
            .setBlocking(false).setMetered(false)
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
        val routed = routedApplications(selected.includedApps) { name ->
            runCatching { packageManager.getApplicationInfo(name, PackageManager.ApplicationInfoFlags.of(0)) }.isSuccess
        }
        (selected.includedApps - routed.toSet()).forEach { TunnelState.log("Skipped a selected app that is not installed: $it") }
        routed.forEach { builder.addAllowedApplication(it) }
        // Android attributes loopback connections only for apps a VPN covers;
        // the internal relay and listener rely on that to admit only this app.
        // Its own non-loopback sockets are protected gateway connections.
        if (routed.isNotEmpty() && packageName !in routed) builder.addAllowedApplication(packageName)
        val replacement = builder.establish() ?: error("Android revoked VPN permission")
        val previous = tun
        tun = replacement
        previous?.close()
    }

    override fun bindEngine(): Boolean {
        bound = bindService(Intent(this, EngineService::class.java), connection, Context.BIND_AUTO_CREATE)
        return bound
    }
    override fun startEngine(profile: TunnelProfile, session: String, gateways: GatewayPlan) {
        val worker = engine ?: return
        val encoded = gateways.encode()
        scope.launch(Dispatchers.IO) {
            try { if (controller.accepts(session)) worker.start(profile.id, session, encoded, callback) }
            catch (_: Exception) { scope.launch(Dispatchers.Main) { controller.engineUnreachable(session) } }
        }
    }
    override fun stopEngine(session: String) { runCatching { engine?.stop(session) } }
    override suspend fun stopEngineAndWait(session: String): Boolean {
        val worker = engine
        // The owner stays bound until all earlier worker cleanup has released
        // its TUN duplicates.
        return withContext(Dispatchers.IO) { worker == null || runCatching { worker.stopAndWait(session) }.getOrDefault(false) }
    }
    override fun unbindEngine() {
        if (bound) runCatching { unbindService(connection) }
        bound = false
        engine = null
    }
    override fun engineNetworkChanged(session: String, sameNetwork: Boolean) {
        runCatching { engine?.networkChanged(session, sameNetwork) }
    }

    override fun log(message: String) = TunnelState.log(message)
    override fun notify(message: String) {
        getSystemService(android.app.NotificationManager::class.java).notify(1, notification(message))
    }
    override fun stopService() { stopForeground(STOP_FOREGROUND_REMOVE); stopSelf() }

    private fun notification(message: String): Notification {
        val open = PendingIntent.getActivity(this, 0, Intent(this, io.github.cysin.sslsockspro.ui.MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val stop = PendingIntent.getService(this, 1, Intent(this, ConnectionService::class.java).setAction(STOP), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        // The lock screen shows only this generic version, never connection details.
        val public = Notification.Builder(this, "tunnel").setSmallIcon(R.drawable.ic_tunnel).setContentTitle("SSLSocks Pro")
            .setContentText("Tunnel status is hidden on the lock screen").build()
        return Notification.Builder(this, "tunnel").setSmallIcon(R.drawable.ic_tunnel).setContentTitle("SSLSocks Pro")
            .setContentText(message.take(160)).setContentIntent(open).setOngoing(true)
            .setVisibility(Notification.VISIBILITY_PRIVATE).setPublicVersion(public)
            .apply { if (!isAlwaysOn) addAction(Notification.Action.Builder(null, "Disconnect", stop).build()) }.build()
    }

    companion object {
        const val STOP = "io.github.cysin.sslsockspro.STOP"
        const val PROFILE = "profile"

        /** Installed selected apps. A selection whose apps are all missing must
         * fail instead of silently becoming an all-app VPN. */
        internal fun routedApplications(selected: List<String>, installed: (String) -> Boolean): List<String> {
            val available = selected.filter(installed)
            require(selected.isEmpty() || available.isNotEmpty()) {
                "None of the selected apps are installed. Choose apps again or route all apps."
            }
            return available
        }
        fun start(context: Context, profile: TunnelProfile) = context.startForegroundService(Intent(context, ConnectionService::class.java).putExtra(PROFILE, profile.id))
        fun stop(context: Context) = context.startService(Intent(context, ConnectionService::class.java).setAction(STOP))
    }
}
