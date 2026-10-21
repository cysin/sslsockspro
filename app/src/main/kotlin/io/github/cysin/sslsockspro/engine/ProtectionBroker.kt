package io.github.cysin.sslsockspro.engine

import android.net.LocalServerSocket
import android.os.ParcelFileDescriptor
import android.os.Process
import java.io.DataInputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/** Native processes pass socket descriptors before connect(); the VPN owner
 * marks them as protected without JVM-wide signal or routing changes. After
 * accept() on a guarded loopback listener they ask whether the client belongs
 * to this app ('U'); other apps' connections are closed by the caller.
 */
class ProtectionBroker(
    private val callback: IEngineCallback,
    private val session: String,
    private val ownerCheck: (InetSocketAddress, InetSocketAddress) -> Boolean = { _, _ -> false },
) : AutoCloseable {
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
                var allowed = false
                try {
                    if (command == 'P'.code && descriptors.size == 1) {
                        ParcelFileDescriptor.dup(descriptors[0]).use { allowed = callback.protectSocket(it, session) }
                    } else if (command == 'U'.code && descriptors.isEmpty()) {
                        val (peer, local) = endpoints(DataInputStream(socket.inputStream))
                        allowed = ownerCheck(peer, local)
                    }
                } finally { descriptors.forEach { descriptor -> runCatching { android.system.Os.close(descriptor) } } }
                socket.outputStream.write(if (allowed) 'Y'.code else 'N'.code)
                socket.outputStream.flush()
            } catch (_: Exception) { }
            finally { clients.remove(socket); runCatching { socket.close() } }
        }
    }, "native-socket-protection").apply { isDaemon = true; start() }

    /** family(1: 4 or 6), peer address(16), peer port(2), local address(16),
     * local port(2); IPv4 addresses occupy the first four address bytes. */
    private fun endpoints(input: DataInputStream): Pair<InetSocketAddress, InetSocketAddress> {
        val family = input.readUnsignedByte()
        require(family == 4 || family == 6)
        fun endpoint(): InetSocketAddress {
            val address = ByteArray(16).also(input::readFully)
            val port = input.readUnsignedShort()
            return InetSocketAddress(InetAddress.getByAddress(if (family == 4) address.copyOf(4) else address), port)
        }
        return endpoint() to endpoint()
    }

    override fun close() {
        running = false
        runCatching { server.close() }
        clients.forEach { runCatching { it.close() } }
        if (Thread.currentThread() !== thread) thread.join(6000)
    }
}
