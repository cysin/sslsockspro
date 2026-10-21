package io.github.cysin.sslsockspro.engine

/* Android management/TUN integration follows OpenVPN for Android 0.7.68.
 * Copyright (c) 2012-2026 Arne Schwabe and SSLSocks Pro contributors.
 * GPL-2.0-or-later with the upstream OpenSSL/Apache linking exceptions.
 * Unlike reflection-based descriptor conversion, this uses public Android APIs.
 */
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.os.ParcelFileDescriptor
import android.system.Os
import io.github.cysin.sslsockspro.model.TunnelProfile
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.FileDescriptor
import java.net.InetAddress
import java.util.ArrayDeque
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

class OpenVpnManagement(
    private val path: File,
    private val profile: TunnelProfile,
    private val callback: IEngineCallback,
    private val session: String,
) : AutoCloseable {
    private val socket = LocalSocket()
    private val descriptors = ArrayDeque<FileDescriptor>()
    private val network = JSONObject().put("mtu", 1500).put("dns", JSONArray())
    @Volatile private var running = true
    private var thread: Thread? = null
    private val holds = Executors.newSingleThreadScheduledExecutor { task -> Thread(task, "openvpn-backoff").apply { isDaemon = true } }
    private var holdRelease: ScheduledFuture<*>? = null

    fun start() {
        var connected = false
        for (attempt in 0 until 100) {
            if (!running) break
            try { socket.connect(LocalSocketAddress(path.absolutePath, LocalSocketAddress.Namespace.FILESYSTEM)); connected = true; break }
            catch (_: Exception) { Thread.sleep(100) }
        }
        check(connected) { "OpenVPN management interface did not start" }
        command("state on\nbytecount 1\nhold release\n")
        thread = Thread({ read() }, "openvpn-events").apply { isDaemon = true; start() }
    }

    private fun read() {
        val buffer = ByteArray(4096)
        var pending = ""
        try {
            while (running) {
                val count = socket.inputStream.read(buffer)
                if (count < 0) break
                socket.ancillaryFileDescriptors.orEmpty().forEach(descriptors::addLast)
                pending += buffer.copyOf(count).toString(Charsets.UTF_8)
                require(pending.length <= 16384) { "OpenVPN returned an oversized management event" }
                while (pending.contains('\n')) {
                    val line = pending.substringBefore('\n').trimEnd('\r')
                    pending = pending.substringAfter('\n')
                    event(line)
                }
            }
        } catch (_: Exception) {
            if (running) runCatching { callback.event(EngineEvent.OPENVPN_CONTROL_LOST, "", session) }
        } finally {
            while (descriptors.isNotEmpty()) runCatching { Os.close(descriptors.removeFirst()) }
        }
    }

    private fun event(line: String) {
        when {
            line.startsWith(">NEED-OK:") -> need(line.substringAfter(':'))
            line.startsWith(">HOLD:") -> {
                val seconds = line.substringAfterLast(':').toLongOrNull()?.coerceIn(0, 30) ?: 1
                holdRelease?.cancel(false)
                holdRelease = holds.schedule({ if (running) runCatching { command("hold release\n") } }, seconds, TimeUnit.SECONDS)
            }
            line.startsWith(">STATE:") -> {
                val state = line.substringAfter(':').split(',').getOrNull(1)
                when (state) {
                    "CONNECTED" -> callback.event(EngineEvent.CONNECTED, "", session)
                    "RECONNECTING" -> callback.event(EngineEvent.RECONNECTING, "", session)
                    "EXITING" -> if (running) callback.event(EngineEvent.OPENVPN_ENDED, "", session)
                }
            }
            line.startsWith(">BYTECOUNT:") -> {
                val values = line.substringAfter(':').split(',')
                if (values.size == 2) callback.traffic(values[0].toLong(), values[1].toLong(), session)
            }
            line.startsWith(">PASSWORD:") -> {
                if (line.contains("Verification Failed")) {
                    callback.event(EngineEvent.AUTH_REJECTED, "", session)
                    command("signal SIGTERM\n")
                    return
                }
                val name = line.substringAfter('\'').substringBefore('\'')
                if (name == "Auth" && profile.openVpnUsername.isNotBlank()) {
                    command("username \"Auth\" ${quoted(profile.openVpnUsername)}\npassword \"Auth\" ${quoted(profile.openVpnPassword)}\n")
                } else if (name in setOf("Private Key", "PKCS#12") && profile.openVpnKeyPassphrase.isNotBlank()) {
                    command("password ${quoted(name)} ${quoted(profile.openVpnKeyPassphrase)}\n")
                } else callback.event(EngineEvent.CREDENTIALS_REQUIRED, "", session)
            }
            line.startsWith(">FATAL:") -> callback.event(EngineEvent.OPENVPN_FATAL, "", session)
        }
    }

    private fun need(argument: String) {
        val name = argument.substringAfter('\'').substringBefore('\'')
        val extra = argument.substringAfter(':', "").trim()
        var response = "ok"
        when (name) {
            "PROTECTFD" -> {
                val descriptor = descriptors.pollFirst()
                var success = false
                if (descriptor != null) try {
                    ParcelFileDescriptor.dup(descriptor).use { success = callback.protectSocket(it, session) }
                } finally { Os.close(descriptor) }
                if (!success) response = "cancel"
            }
            "DNSSERVER", "DNS6SERVER" -> {
                require(extra.matches(Regex("[0-9a-fA-F:.]+")))
                network.getJSONArray("dns").put(extra)
            }
            "IFCONFIG" -> {
                val fields = extra.split(' ')
                require(fields.size >= 4 && fields[0].matches(Regex("[0-9.]+")))
                val prefix = if (fields[3] == "subnet") InetAddress.getByName(fields[1]).address.sumOf { Integer.bitCount(it.toInt() and 255) } else 32
                network.put("ipv4", fields[0]).put("prefix", prefix).put("mtu", fields[2].toInt())
            }
            "IFCONFIG6" -> {
                val fields = extra.split(' ')
                require(fields.size >= 2)
                network.put("ipv6", fields[0]).put("mtu", fields[1].toInt())
            }
            "PERSIST_TUN_ACTION" -> response = "OPEN_BEFORE_CLOSE"
            "OPENTUN" -> {
                val tun = callback.acquireTun(network.toString(), session)
                if (tun == null) response = "cancel"
                else {
                    tun.use {
                        socket.setFileDescriptorsForSend(arrayOf(it.fileDescriptor))
                        try { command("needok 'OPENTUN' ok\n") }
                        finally { socket.setFileDescriptorsForSend(null) }
                    }
                    return
                }
            }
            "ROUTE", "ROUTE6", "DNSDOMAIN", "HTTPPROXY" -> Unit
            else -> response = "cancel"
        }
        command("needok '$name' $response\n")
    }

    fun byteCount(seconds: Int) {
        if (running) runCatching { command("bytecount $seconds\n") }
    }

    @Synchronized private fun command(value: String) {
        socket.outputStream.write(value.toByteArray(Charsets.UTF_8)); socket.outputStream.flush()
    }
    override fun close() {
        requestStop()
        if (Thread.currentThread() !== thread) thread?.join(2000)
    }
    fun requestStop() {
        running = false
        holdRelease?.cancel(false)
        holds.shutdownNow()
        runCatching { socket.close() }
    }
    private fun quoted(value: String): String {
        require(value.none { it == '\n' || it == '\r' || it == '\u0000' }) { "Invalid OpenVPN credential" }
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\""
    }
}
