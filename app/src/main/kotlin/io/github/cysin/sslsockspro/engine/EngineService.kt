package io.github.cysin.sslsockspro.engine

import android.app.Service
import android.content.Intent
import android.os.Binder
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import android.os.Process
import io.github.cysin.sslsockspro.TunnelApplication
import io.github.cysin.sslsockspro.config.Endpoint
import io.github.cysin.sslsockspro.config.GatewayPlan
import io.github.cysin.sslsockspro.config.StunnelDocument
import io.github.cysin.sslsockspro.data.Credentials
import io.github.cysin.sslsockspro.data.KeystoreKeys
import io.github.cysin.sslsockspro.data.OpenVpnDocument
import io.github.cysin.sslsockspro.model.ConnectionMode
import io.github.cysin.sslsockspro.model.DnsMode
import io.github.cysin.sslsockspro.model.ProxyKind
import io.github.cysin.sslsockspro.model.TunnelProfile
import io.github.cysin.sslsockspro.network.BackendProbe
import io.github.cysin.sslsockspro.network.DnsCache
import io.github.cysin.sslsockspro.network.DnsService
import io.github.cysin.sslsockspro.network.FakeDns
import io.github.cysin.sslsockspro.network.SocksRelay
import io.github.cysin.sslsockspro.network.TunneledDns
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.Job
import org.xbill.DNS.DClass
import org.xbill.DNS.Message
import org.xbill.DNS.Name
import org.xbill.DNS.Type
import java.io.File
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** Bound foreground-owner worker. A FIFO command executor serializes start,
 * stop and profile switches; IPC requests never block the Android UI thread.
 */
class EngineService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + dispatcher)
    @Volatile private var active: Runtime? = null
    private val control = Any()
    @Volatile private var requestedSession: String? = null
    @Volatile private var statsInterval = 1000L
    private val binder = object : IEngineService.Stub() {
        override fun start(profileId: String, sessionId: String, resolvedGateways: String, callback: IEngineCallback) {
            check(Binder.getCallingUid() == Process.myUid())
            synchronized(control) {
                requestedSession = sessionId
                active?.requestStop()
                scope.launch {
                    active?.close(); active = null
                    val runtime = Runtime(sessionId, callback)
                    synchronized(control) {
                        if (requestedSession != sessionId) return@launch
                        active = runtime
                    }
                    try {
                        val profile = (application as TunnelApplication).profiles.read().profiles.firstOrNull { it.id == profileId }
                            ?: throw IllegalArgumentException("Profile was removed")
                        runtime.start(profile, GatewayPlan.decode(resolvedGateways))
                    } catch (failure: Exception) {
                        val cancelled = requestedSession != sessionId || !runtime.isRunning
                        runtime.close()
                        if (active === runtime) active = null
                        if (!cancelled) runCatching {
                            callback.event(if (failure is IllegalArgumentException) EngineEvent.CONFIG_ERROR else EngineEvent.START_FAILED,
                                failure.message.orEmpty(), sessionId)
                        }
                    }
                }
            }
        }
        override fun stop(sessionId: String) {
            check(Binder.getCallingUid() == Process.myUid())
            synchronized(control) {
                if (requestedSession == sessionId) requestedSession = null
                active?.takeIf { it.id == sessionId }?.requestStop()
                scope.launch { if (active?.id == sessionId) { active?.close(); active = null } }
            }
        }
        override fun stopAndWait(sessionId: String): Boolean {
            check(Binder.getCallingUid() == Process.myUid())
            stop(sessionId)
            // An explicit disconnect forgets cached and synthetic DNS answers.
            dnsStates.clear()
            // The owner calls this on an IO thread and stays bound until all
            // earlier cleanup has released the worker's TUN duplicates.
            return runCatching {
                executor.submit { }.get(10, TimeUnit.SECONDS)
                true
            }.getOrDefault(false)
        }
        override fun networkChanged(sessionId: String, sameNetwork: Boolean) {
            check(Binder.getCallingUid() == Process.myUid())
            active?.takeIf { it.id == sessionId }?.networkChanged(sameNetwork)
        }
        override fun setStatsInterval(sessionId: String, milliseconds: Long) {
            check(Binder.getCallingUid() == Process.myUid())
            // May arrive before the session's runtime exists; it starts from this value.
            statsInterval = milliseconds.coerceIn(0, 60_000)
            active?.takeIf { it.id == sessionId }?.statsIntervalMs = statsInterval
        }
        override fun testConnection(sessionId: String): Long {
            check(Binder.getCallingUid() == Process.myUid())
            return active?.takeIf { it.id == sessionId }?.test() ?: -1
        }
        override fun answerChallenge(sessionId: String, response: String) {
            check(Binder.getCallingUid() == Process.myUid())
            active?.takeIf { it.id == sessionId }?.answerChallenge(response)
        }
        override fun versions(): String {
            check(Binder.getCallingUid() == Process.myUid())
            return assets.open("native-versions.json").bufferedReader().use { it.readText() }
        }
    }

    override fun onBind(intent: Intent): IBinder = binder
    override fun onCreate() {
        super.onCreate()
        // Only generated files live here; archive entries are never extracted.
        // Native children receive a parent-death signal when the worker dies.
        executor.execute { File(noBackupFilesDir, "runtime").deleteRecursively() }
    }
    override fun onUnbind(intent: Intent?): Boolean {
        requestedSession = null
        active?.requestStop()
        scope.launch { active?.close(); active = null }
        return false
    }
    override fun onDestroy() {
        requestedSession = null
        active?.requestStop()
        executor.execute { active?.close(); active = null }
        scope.cancel(); super.onDestroy()
    }

    private inner class Runtime(val id: String, private val callback: IEngineCallback) : AutoCloseable {
        private val directory = File(noBackupFilesDir, "runtime/$id")
        @Volatile private var broker: ProtectionBroker? = null
        @Volatile private var stunnel: java.lang.Process? = null
        @Volatile private var openvpn: java.lang.Process? = null
        @Volatile private var management: OpenVpnManagement? = null
        private var hev: HevEngine? = null
        private var tun: ParcelFileDescriptor? = null
        private var relay: SocksRelay? = null
        @Volatile private var dns: TunneledDns? = null
        @Volatile private var resolver: DnsService? = null
        @Volatile private var running = true
        @Volatile var statsIntervalMs = statsInterval
            set(value) { field = value; applyOpenVpnStats() }
        private var nextStats = 0L
        private var lastTraffic = -1L to -1L
        @Volatile private var startingThread: Thread? = null
        private val closed = AtomicBoolean()
        private var watchdog: Job? = null
        private var managementPath: File? = null
        private var logOffset = 0L
        private var partialLogLine = ""
        private val nativeLog = LogLimiter()
        private var healthFailures = 0
        private var nextHealthCheck = System.nanoTime() + TimeUnit.SECONDS.toNanos(30)
        private var nextDiagnostics = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        val isRunning get() = running

        fun start(profile: TunnelProfile, gateways: GatewayPlan) {
            startingThread = Thread.currentThread()
            try { startEngines(profile, gateways) }
            finally { startingThread = null; Thread.interrupted() }
        }

        private fun checkRunning() { if (!running) throw InterruptedException("Connection was cancelled") }

        private fun startEngines(profile: TunnelProfile, gateways: GatewayPlan) {
            checkRunning()
            require(id.matches(Regex("[a-fA-F0-9-]{36}")))
            directory.mkdirs()
            val credentialPath = Credentials.materialize(profile, directory)
            val hosts = gateways.hosts
            val allowed = gateways.allowed.joinToString(",")
            // In VPN modes the selected tunnel is internal: a per-session port
            // that only this app may use, reached only through the relay.
            val internal = profile.mode == ConnectionMode.PROXY_VPN || (profile.mode == ConnectionMode.OPENVPN && profile.openVpnViaStunnel)
            val owner = LoopbackOwner(this@EngineService)
            val guarded = internal && owner.available()
            if (internal && !guarded) log("This Android build cannot attribute loopback connections; the internal tunnel uses a private random port without an owner check")
            val ownerCheck: (java.net.InetSocketAddress, java.net.InetSocketAddress) -> Boolean =
                if (guarded) owner::owned else { _, _ -> true }
            broker = ProtectionBroker(callback, id, ownerCheck)
            checkRunning()
            var document: StunnelDocument? = null
            var upstream: Endpoint? = null
            if (profile.mode != ConnectionMode.OPENVPN || profile.openVpnViaStunnel) {
                document = StunnelDocument.parse(profile.config)
                val selected = section(profile, document)
                if (internal) upstream = Endpoint("127.0.0.1", freeLoopbackPort())
                val listeners = upstream?.let { mapOf(selected to it) }.orEmpty()
                val config = File(directory, "stunnel.conf")
                config.writeText(document.renderRuntime(directory.absolutePath, credentialPath, hosts, listeners))
                stunnel = process("libstunnel_exec.so", config, allowed, guardedPorts = if (guarded) listOf(upstream!!.port) else emptyList())
                checkRunning()
                for (section in document.sections) {
                    val listener = listeners[section] ?: document.listener(section)
                    awaitListener(listener.host, listener.port, stunnel!!)
                }
            }
            when (profile.mode) {
                ConnectionMode.LOCAL_PROXY -> {
                    // Generic TCP backends need not speak HTTP or SOCKS. A
                    // listener is ready; remote mTLS is verified on first use.
                    callback.event(EngineEvent.LISTENING, "", id)
                }
                ConnectionMode.PROXY_VPN -> {
                    val state = dnsStates.compute(profile.id) { _, existing ->
                        existing?.takeIf { it.mode == profile.dnsMode } ?: DnsState(profile.dnsMode, DnsCache(),
                            if (profile.dnsMode == DnsMode.PROXY) FakeDns() else null)
                    }!!
                    relay = SocksRelay(upstream!!, backend(profile, upstream), ownerCheck, profile.backendCredentials(),
                        target = state.synthetic?.let { names -> names::target } ?: { it },
                        keepWarm = { power.isInteractive }) { query, reply -> resolver!!.resolve(query, reply) }
                    val relayEndpoint = Endpoint("127.0.0.1", relay!!.port)
                    dns = TunneledDns(profile.dnsEndpoint, relayEndpoint, ProxyKind.HTTP_CONNECT, profile.suppressServiceBindings,
                        relay!!.username to relay!!.password)
                    resolver = DnsService(dns!!::resolveAsync, state.cache, state.synthetic, profile.proxyIpv6)
                    probe(dns!!)
                    checkRunning()
                    tun = callback.acquireTun("{}", id) ?: error("VPN interface is unavailable")
                    val config = File(directory, "hev.yml")
                    // The TUN is virtual: a large MTU means fewer packets for
                    // the same data. It must match the owner's TUN MTU.
                    config.writeText("""
                        tunnel:
                          mtu: $PROXY_MTU
                          ipv4: 198.18.0.1
                          ipv6: 'fd00:5353::1'
                          icmp: 'off'
                        socks5:
                          address: 127.0.0.1
                          port: ${relay!!.port}
                          username: '${relay!!.username}'
                          password: '${relay!!.password}'
                          udp: 'udp'
                          pipeline: true
                        misc:
                          max-session-count: 1024
                          connect-timeout: 15000
                          tcp-read-write-timeout: 1800000
                          log-level: warn
                    """.trimIndent() + "\n")
                    hev = HevEngine()
                    // HEV borrows an externally supplied TUN descriptor; it
                    // only closes interfaces it opens itself. Keep ownership
                    // here and close it after the packet engine has stopped.
                    if (!hev!!.TProxyStartService(config.absolutePath, tun!!.fd)) {
                        error("Could not start the VPN packet engine")
                    }
                    callback.event(EngineEvent.CONNECTED, "", id)
                }
                ConnectionMode.OPENVPN -> {
                    val managementSocket = File(cacheDir, "ovpn-$id.sock")
                    managementPath = managementSocket
                    managementSocket.delete()
                    val proxy = if (profile.openVpnViaStunnel) {
                        relay = SocksRelay(upstream!!, backend(profile, upstream), ownerCheck, profile.backendCredentials()) { _, _ ->
                            error("OpenVPN resolves DNS inside its tunnel")
                        }
                        val authentication = File(directory, "relay-auth")
                        authentication.writeText(relay!!.username + "\n" + relay!!.password + "\n")
                        authentication.setReadable(false, false); authentication.setReadable(true, true)
                        OpenVpnDocument.HttpProxyRoute(Endpoint("127.0.0.1", relay!!.port), authentication.absolutePath)
                    } else null
                    val externalKey = profile.openVpnKeyAlias.isNotEmpty()
                    require(!externalKey || KeystoreKeys.present(profile.openVpnKeyAlias)) {
                        "The OpenVPN client key is held only by the phone where this profile was imported. Import the client package again on this phone."
                    }
                    val config = File(directory, "openvpn.conf")
                    val text = OpenVpnDocument.runtime(profile.openVpnConfig, credentialPath, managementSocket.absolutePath, proxy, hosts, externalKey)
                    config.writeText(text)
                    openvpn = process("libopenvpn_exec.so", config, allowed)
                    checkRunning()
                    management = OpenVpnManagement(managementSocket, profile, callback, id)
                    management!!.start()
                    applyOpenVpnStats()
                }
            }
            checkRunning()
            // Child exits arrive as events; the loop only polls what has no event.
            for (child in listOfNotNull(stunnel, openvpn)) Thread({
                runCatching { child.waitFor() }
                if (running) runCatching { callback.event(EngineEvent.ENGINE_STOPPED, "", id) }
            }, "native-exit-watch").apply { isDaemon = true; start() }
            watchdog = scope.launch(Dispatchers.IO) {
                while (running) {
                    // Fast while counters are displayed; otherwise rare wakeups.
                    delay(if (statsIntervalMs > 0) 1000 else 5000)
                    if (!running) break
                    if (hev != null && !hev!!.TProxyIsRunning()) {
                        runCatching { callback.event(EngineEvent.ENGINE_STOPPED, "", id) }
                        break
                    }
                    // OpenVPN reports its own counters; its relay carries only OpenVPN.
                    relay?.takeIf { profile.mode == ConnectionMode.PROXY_VPN }?.let { relay ->
                        val interval = statsIntervalMs
                        val traffic = relay.received.get() to relay.sent.get()
                        if (interval > 0 && System.nanoTime() >= nextStats && traffic != lastTraffic) {
                            nextStats = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(interval)
                            lastTraffic = traffic
                            runCatching { callback.traffic(traffic.first, traffic.second, id) }
                        }
                    }
                    try { rotateLog() }
                    catch (_: IOException) {
                        if (running) runCatching { callback.event(EngineEvent.DIAGNOSTICS_FAILED, "Could not maintain the native diagnostic log", id) }
                        break
                    }
                    readNativeLog()
                    if (relay != null && System.nanoTime() >= nextDiagnostics) {
                        nextDiagnostics = System.nanoTime() + TimeUnit.SECONDS.toNanos(30)
                        log(relay!!.diagnostics())
                    }
                    if (profile.mode == ConnectionMode.PROXY_VPN && System.nanoTime() >= nextHealthCheck) {
                        // Each probe wakes the radio, so probe rarely while the
                        // screen is off and not at all while traffic proves the
                        // tunnel works. One slow or failed answer must not tear
                        // down every connection; three consecutive failures do.
                        val interval = TimeUnit.SECONDS.toNanos(if (power.isInteractive) 30 else 300)
                        try {
                            if (healthFailures > 0 || System.nanoTime() - relay!!.lastUpstreamSuccess.get() > interval) probe(dns!!)
                            healthFailures = 0
                            nextHealthCheck = System.nanoTime() + interval
                        } catch (_: Exception) {
                            if (++healthFailures >= HEALTH_FAILURES) {
                                if (running) runCatching { callback.event(EngineEvent.HEALTH_FAILED, "", id) }
                                break
                            }
                            log("Tunnel health check failed ($healthFailures/$HEALTH_FAILURES); checking again shortly")
                            nextHealthCheck = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
                        }
                    }
                }
            }
        }

        /** The configured backend unless the server identifies itself
         * otherwise; positive identifications are remembered per profile. */
        private fun backend(profile: TunnelProfile, upstream: Endpoint): ProxyKind {
            val detected = detectedBackends[profile.id] ?: BackendProbe.detect(upstream)?.also { detectedBackends[profile.id] = it }
            if (detected != null && detected != profile.proxyKind) runCatching { callback.event(EngineEvent.NOTICE,
                "The server answered as ${if (detected == ProxyKind.SOCKS5) "SOCKS5" else "HTTP CONNECT"}; using it for this connection. Update the profile's backend type.", id) }
            return detected ?: profile.proxyKind
        }

        /** OpenVPN reports its own counters; zero disables them. */
        private fun applyOpenVpnStats() {
            val interval = statsIntervalMs
            management?.byteCount(if (interval <= 0) 0 else maxOf(1, (interval / 1000).toInt()))
        }

        private fun section(profile: TunnelProfile, document: StunnelDocument): String =
            profile.selectedSection.takeIf { it in document.sections } ?: document.sections.first()

        private fun probe(dns: TunneledDns) {
            val query = Message.newQuery(org.xbill.DNS.Record.newRecord(Name.fromString("one.one.one.one."), Type.A, DClass.IN))
            val answer = Message(dns.resolve(query.toWire()))
            require(answer.header.rcode == 0 && answer.header.getCount(org.xbill.DNS.Section.ANSWER) > 0) { "Tunnel DNS health check failed" }
        }

        private fun freeLoopbackPort(): Int = java.net.ServerSocket(0, 1, java.net.InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))).use { it.localPort }

        private fun process(binary: String, configuration: File, allowed: String, guardedPorts: List<Int> = emptyList()): java.lang.Process {
            val executable = File(applicationInfo.nativeLibraryDir, binary)
            check(executable.canExecute()) { "Native component is missing or not executable: $binary" }
            val builder = ProcessBuilder(executable.absolutePath, if (binary.contains("openvpn")) "--config" else configuration.absolutePath)
            if (binary.contains("openvpn")) builder.command().add(configuration.absolutePath)
            builder.directory(directory).redirectErrorStream(true)
            builder.environment()["SSP_PROTECT_SOCKET"] = broker!!.name
            builder.environment()["SSP_ALLOWED_PEERS"] = allowed
            if (guardedPorts.isNotEmpty()) builder.environment()["SSP_GUARDED_PORTS"] = guardedPorts.joinToString(",")
            builder.environment()["SSP_PARENT_PID"] = Process.myPid().toString()
            builder.environment()["OPENSSL_CONF"] = "/dev/null"
            val child = builder.start()
            scope.launch(Dispatchers.IO) {
                try { child.inputStream.bufferedReader().use { reader ->
                    val line = StringBuilder()
                    while (running) {
                        val character = reader.read()
                        if (character < 0) break
                        if (character == '\n'.code) {
                            nativeLine(line.toString())
                            line.clear()
                        } else if (line.length < 2048) line.append(character.toChar())
                    }
                } } catch (_: IOException) {
                    // Android closes process pipes during destroy(). A blocked
                    // diagnostic read must not crash the worker on disconnect.
                    if (running) runCatching { callback.event(EngineEvent.DIAGNOSTICS_FAILED, "Native diagnostic stream stopped", id) }
                }
            }
            return child
        }

        private fun awaitListener(host: String, port: Int, child: java.lang.Process) {
            for (attempt in 0 until 100) {
                checkRunning()
                if (!child.isAlive) { readNativeLog(); throw IllegalArgumentException("stunnel rejected the configuration. See the connection log.") }
                try { Socket().use { it.connect(InetSocketAddress(host, port), 100) }; return }
                catch (_: Exception) { Thread.sleep(50) }
            }
            error("Local stunnel listener did not start")
        }

        private fun rotateLog() {
            val file = File(directory, "stunnel.log")
            if (file.length() > 1024 * 1024) {
                // Truncating an owned log preserves the native writer's open
                // descriptor and bounds disk usage without process signals.
                java.io.RandomAccessFile(file, "rw").use { it.setLength(0) }
                logOffset = 0
            }
        }

        private fun nativeLine(line: String) {
            if (line.isNotBlank()) nativeLog.admit(line).forEach(::log)
        }

        private fun log(message: String) {
            if (!message.contains("PRIVATE KEY") && !message.contains("password", true))
                runCatching { callback.event(EngineEvent.LOG, message.take(1024), id) }
        }

        private fun readNativeLog() {
            val file = File(directory, "stunnel.log")
            if (!file.isFile) return
            runCatching {
                java.io.RandomAccessFile(file, "r").use { input ->
                    if (input.length() < logOffset) { logOffset = 0; partialLogLine = "" }
                    input.seek(logOffset)
                    val buffer = ByteArray(minOf(65536L, input.length() - logOffset).toInt())
                    input.readFully(buffer)
                    logOffset += buffer.size
                    // Keep an unfinished last line for the next read; the
                    // limiter, not truncation, bounds what reaches the UI.
                    val lines = (partialLogLine + buffer.toString(Charsets.UTF_8)).split('\n')
                    partialLogLine = lines.last().take(2048)
                    lines.dropLast(1).forEach(::nativeLine)
                }
            }
        }

        fun answerChallenge(response: String) { management?.answerChallenge(response) }

        /** Times one DoH query through the whole tunnel. */
        fun test(): Long {
            val resolver = dns ?: return -1
            val started = System.nanoTime()
            return runCatching { probe(resolver); TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started) }.getOrDefault(-1)
        }

        /** Sockets bound to the previous network fail; pooled DoH connections
         * must not be reused for later queries. */
        fun networkChanged(sameNetwork: Boolean) {
            if (!running) return
            dns?.evictConnections()
            relay?.networkChanged()
            management?.networkChange(sameNetwork)
            // Confirm the tunnel soon; repeated failures trigger a full reconnect.
            healthFailures = 0
            nextHealthCheck = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
            log(if (sameNetwork) "Network addresses changed" else "Physical network changed")
        }

        /** Nonblocking interruption from Binder/UI threads. Resource disposal
         * stays on the command executor, after startup leaves its critical path. */
        fun requestStop() {
            running = false
            dns?.cancelPending()
            management?.requestStop()
            stunnel?.destroy(); openvpn?.destroy()
            startingThread?.takeUnless { it === Thread.currentThread() }?.interrupt()
        }

        override fun close() {
            if (!closed.compareAndSet(false, true)) return
            requestStop()
            Thread.interrupted()
            watchdog?.cancel()
            runCatching { management?.close() }
            runCatching { hev?.TProxyStopService() }
            runCatching { relay?.close() }; runCatching { dns?.close() }
            for (child in listOfNotNull(openvpn, stunnel)) {
                runCatching { child.destroy(); if (!child.waitFor(2, TimeUnit.SECONDS)) child.destroyForcibly() }
                if (child.isAlive) runCatching { child.destroyForcibly() }
            }
            runCatching { broker?.close() }; runCatching { tun?.close() }
            directory.deleteRecursively()
            managementPath?.delete()
        }
    }

    private val power by lazy { getSystemService(PowerManager::class.java) }

    /** Cached and synthetic DNS answers outlive reconnects of a profile. */
    private class DnsState(val mode: DnsMode, val cache: DnsCache, val synthetic: FakeDns?)

    companion object {
        /** Must equal the owner's TUN MTU for proxy VPN mode. */
        const val PROXY_MTU = 8500
        private const val HEALTH_FAILURES = 3
        private val dnsStates = java.util.concurrent.ConcurrentHashMap<String, DnsState>()
        private val detectedBackends = java.util.concurrent.ConcurrentHashMap<String, ProxyKind>()
        // Android may recreate a bound service before its previous async
        // cleanup finishes. All instances serialize native startup/cleanup on
        // one process executor, including the global packet-engine JNI state.
        private val executor = Executors.newSingleThreadExecutor { task ->
            Thread(task, "native-engine-commands").apply { isDaemon = true }
        }
        private val dispatcher = executor.asCoroutineDispatcher()
    }
}
