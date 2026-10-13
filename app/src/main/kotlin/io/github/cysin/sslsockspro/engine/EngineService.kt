package io.github.cysin.sslsockspro.engine

import android.app.Service
import android.content.Intent
import android.os.Binder
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.os.Process
import io.github.cysin.sslsockspro.TunnelApplication
import io.github.cysin.sslsockspro.config.StunnelDocument
import io.github.cysin.sslsockspro.data.Credentials
import io.github.cysin.sslsockspro.data.OpenVpnDocument
import io.github.cysin.sslsockspro.model.ConnectionMode
import io.github.cysin.sslsockspro.model.ProxyKind
import io.github.cysin.sslsockspro.model.TunnelProfile
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
import org.json.JSONObject
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
                        runtime.start(profile, JSONObject(resolvedGateways))
                    } catch (failure: Exception) {
                        val cancelled = requestedSession != sessionId || !runtime.isRunning
                        runtime.close()
                        if (active === runtime) active = null
                        if (!cancelled) runCatching {
                            callback.status(if (failure is IllegalArgumentException) "CONFIG_ERROR" else "ERROR",
                                failure.message ?: "Native engine initialization failed", sessionId)
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
        @Volatile private var running = true
        @Volatile private var startingThread: Thread? = null
        private val closed = AtomicBoolean()
        private var watchdog: Job? = null
        private var managementPath: File? = null
        private var logOffset = 0L
        private var nextHealthCheck = System.nanoTime() + TimeUnit.SECONDS.toNanos(30)
        private var nextDiagnostics = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        val isRunning get() = running

        fun start(profile: TunnelProfile, gateways: JSONObject) {
            startingThread = Thread.currentThread()
            try { startEngines(profile, gateways) }
            finally { startingThread = null; Thread.interrupted() }
        }

        private fun checkRunning() { if (!running) throw InterruptedException("Connection was cancelled") }

        private fun startEngines(profile: TunnelProfile, gateways: JSONObject) {
            checkRunning()
            require(id.matches(Regex("[a-fA-F0-9-]{36}")))
            directory.mkdirs()
            val credentialPath = Credentials.materialize(profile, directory)
            val hosts = gateways.keys().asSequence().filter { it != "allowed" }.associateWith { gateways.getString(it) }
            broker = ProtectionBroker(callback, id)
            checkRunning()
            val allowed = gateways.getJSONArray("allowed").let { array -> (0 until array.length()).joinToString(",") { array.getString(it) } }
            var document: StunnelDocument? = null
            if (profile.mode != ConnectionMode.OPENVPN || profile.openVpnViaStunnel) {
                document = StunnelDocument.parse(profile.config)
                val config = File(directory, "stunnel.conf")
                config.writeText(document.renderRuntime(directory.absolutePath, credentialPath, hosts))
                stunnel = process("libstunnel_exec.so", config, allowed)
                checkRunning()
                for (section in document.sections) {
                    val listener = document.listener(section)
                    awaitListener(listener.host, listener.port, stunnel!!)
                }
            }
            when (profile.mode) {
                ConnectionMode.LOCAL_PROXY -> {
                    // Generic TCP backends need not speak HTTP or SOCKS. A
                    // listener is ready; remote mTLS is verified on first use.
                    callback.status("LISTENING", "Local TLS listeners ready. Server TLS is verified when an app connects. Phone-wide routing is off.", id)
                }
                ConnectionMode.PROXY_VPN -> {
                    val listener = document!!.listener(section(profile, document))
                    dns = TunneledDns(profile.dnsEndpoint, listener, profile.proxyKind, profile.suppressServiceBindings)
                    probe(dns!!)
                    checkRunning()
                    relay = SocksRelay(listener, profile.proxyKind, dns!!::resolve)
                    tun = callback.acquireTun("{}", id) ?: error("VPN interface is unavailable")
                    val config = File(directory, "hev.yml")
                    config.writeText("""
                        tunnel:
                          mtu: 1500
                          ipv4: 198.18.0.1
                          ipv6: 'fd00:5353::1'
                          icmp: 'off'
                        socks5:
                          address: 127.0.0.1
                          port: ${relay!!.port}
                          username: '${relay!!.username}'
                          password: '${relay!!.password}'
                          udp: 'udp'
                        misc:
                          max-session-count: 128
                          connect-timeout: 15000
                          tcp-read-write-timeout: 43200000
                          log-level: warn
                    """.trimIndent() + "\n")
                    hev = HevEngine()
                    val nativeDescriptor = ParcelFileDescriptor.dup(tun!!.fileDescriptor).detachFd()
                    if (!hev!!.TProxyStartService(config.absolutePath, nativeDescriptor)) {
                        ParcelFileDescriptor.adoptFd(nativeDescriptor).close()
                        error("Could not start the VPN packet engine")
                    }
                    callback.status("CONNECTED", "VPN connected: TCP and DNS tunneled; other UDP blocked", id)
                }
                ConnectionMode.OPENVPN -> {
                    val managementSocket = File(cacheDir, "ovpn-$id.sock")
                    managementPath = managementSocket
                    managementSocket.delete()
                    val proxy = if (profile.openVpnViaStunnel) {
                        val listener = document!!.listener(section(profile, document))
                        (if (profile.proxyKind == ProxyKind.HTTP_CONNECT) "http-proxy" else "socks-proxy") to listener
                    } else null
                    val config = File(directory, "openvpn.conf")
                    val text = OpenVpnDocument.runtime(profile.openVpnConfig, credentialPath, managementSocket.absolutePath, proxy, hosts)
                    config.writeText(text)
                    openvpn = process("libopenvpn_exec.so", config, allowed)
                    checkRunning()
                    management = OpenVpnManagement(managementSocket, profile, callback, id)
                    management!!.start()
                }
            }
            checkRunning()
            watchdog = scope.launch(Dispatchers.IO) {
                while (running) {
                    delay(1000)
                    if (!running) break
                    if (stunnel?.isAlive == false || openvpn?.isAlive == false || (hev != null && !hev!!.TProxyIsRunning())) {
                        runCatching { callback.status("ERROR", "Native network engine stopped; traffic remains blocked", id) }
                        break
                    }
                    relay?.let { runCatching { callback.traffic(it.received.get(), it.sent.get(), id) } }
                    try { rotateLog() }
                    catch (_: IOException) {
                        if (running) runCatching { callback.status("ERROR", "Could not maintain the native diagnostic log", id) }
                        break
                    }
                    readNativeLog()
                    if (relay != null && System.nanoTime() >= nextDiagnostics) {
                        nextDiagnostics = System.nanoTime() + TimeUnit.SECONDS.toNanos(30)
                        log(relay!!.diagnostics())
                    }
                    if (profile.mode == ConnectionMode.PROXY_VPN && System.nanoTime() >= nextHealthCheck) {
                        nextHealthCheck = System.nanoTime() + TimeUnit.SECONDS.toNanos(30)
                        try { probe(dns!!) }
                        catch (_: Exception) {
                            if (running) runCatching { callback.status("ERROR", "Tunnel health check failed; reconnecting without direct DNS or network fallback", id) }
                            break
                        }
                    }
                }
            }
        }

        private fun section(profile: TunnelProfile, document: StunnelDocument): String =
            profile.selectedSection.takeIf { it in document.sections } ?: document.sections.first()

        private fun probe(dns: TunneledDns) {
            val query = Message.newQuery(org.xbill.DNS.Record.newRecord(Name.fromString("one.one.one.one."), Type.A, DClass.IN))
            val answer = Message(dns.resolve(query.toWire()))
            require(answer.header.rcode == 0 && answer.header.getCount(org.xbill.DNS.Section.ANSWER) > 0) { "Tunnel DNS health check failed" }
        }

        private fun process(binary: String, configuration: File, allowed: String): java.lang.Process {
            val executable = File(applicationInfo.nativeLibraryDir, binary)
            check(executable.canExecute()) { "Native component is missing or not executable: $binary" }
            val builder = ProcessBuilder(executable.absolutePath, if (binary.contains("openvpn")) "--config" else configuration.absolutePath)
            if (binary.contains("openvpn")) builder.command().add(configuration.absolutePath)
            builder.directory(directory).redirectErrorStream(true)
            builder.environment()["SSP_PROTECT_SOCKET"] = broker!!.name
            builder.environment()["SSP_ALLOWED_PEERS"] = allowed
            builder.environment()["SSP_PARENT_PID"] = Process.myPid().toString()
            builder.environment()["OPENSSL_CONF"] = "/dev/null"
            val child = builder.start()
            scope.launch(Dispatchers.IO) {
                try { child.inputStream.bufferedReader().use { reader ->
                    var lines = 0
                    val line = StringBuilder()
                    while (running) {
                        val character = reader.read()
                        if (character < 0) break
                        if (character == '\n'.code) {
                            if (++lines <= 200) log(line.toString())
                            line.clear()
                        } else if (line.length < 2048) line.append(character.toChar())
                    }
                } } catch (_: IOException) {
                    // Android closes process pipes during destroy(). A blocked
                    // diagnostic read must not crash the worker on disconnect.
                    if (running) runCatching { callback.status("ERROR", "Native diagnostic stream stopped unexpectedly", id) }
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

        private fun log(message: String) {
            if (!message.contains("PRIVATE KEY") && !message.contains("password", true))
                runCatching { callback.status("LOG", message.take(1024), id) }
        }

        private fun readNativeLog() {
            val file = File(directory, "stunnel.log")
            if (!file.isFile) return
            runCatching {
                java.io.RandomAccessFile(file, "r").use { input ->
                    if (input.length() < logOffset) logOffset = 0
                    input.seek(logOffset)
                    val buffer = ByteArray(minOf(16384L, input.length() - logOffset).toInt())
                    input.readFully(buffer)
                    logOffset += buffer.size
                    buffer.toString(Charsets.UTF_8).lineSequence().filter(String::isNotBlank).take(64).forEach(::log)
                }
            }
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

    companion object {
        // Android may recreate a bound service before its previous async
        // cleanup finishes. All instances serialize native startup/cleanup on
        // one process executor, including the global packet-engine JNI state.
        private val executor = Executors.newSingleThreadExecutor { task ->
            Thread(task, "native-engine-commands").apply { isDaemon = true }
        }
        private val dispatcher = executor.asCoroutineDispatcher()
    }
}
