package io.github.cysin.sslsockspro.engine

import android.net.LocalServerSocket
import android.os.ParcelFileDescriptor
import android.os.Process
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/** Native processes pass socket descriptors before connect(). The app's VPN
 * owner marks them as protected; no JVM-wide signal or routing changes occur.
 */
class ProtectionBroker(private val callback: IEngineCallback, private val session: String) : AutoCloseable {
    val name = "ssp-protect-" + UUID.randomUUID().toString()
    private val server = LocalServerSocket(name)
    private val clients = ConcurrentHashMap.newKeySet<android.net.LocalSocket>()
    @Volatile private var running = true
    private val thread = Thread({
        while (running) {
            val socket = try { server.accept() } catch (_: Exception) { break }
            clients.add(socket)
            try {
                socket.soTimeout = 5000
                if (socket.peerCredentials.uid != Process.myUid()) continue
                val command = socket.inputStream.read()
                val descriptors = socket.ancillaryFileDescriptors.orEmpty()
                var protected = false
                try {
                    if (command == 'P'.code && descriptors.size == 1) {
                        ParcelFileDescriptor.dup(descriptors[0]).use { protected = callback.protectSocket(it, session) }
                    }
                } finally { descriptors.forEach { descriptor -> runCatching { android.system.Os.close(descriptor) } } }
                socket.outputStream.write(if (protected) 'Y'.code else 'N'.code)
                socket.outputStream.flush()
            } catch (_: Exception) { }
            finally { clients.remove(socket); runCatching { socket.close() } }
        }
    }, "native-socket-protection").apply { isDaemon = true; start() }

    override fun close() {
        running = false
        runCatching { server.close() }
        clients.forEach { runCatching { it.close() } }
        if (Thread.currentThread() !== thread) thread.join(6000)
    }
}
