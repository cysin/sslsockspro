package io.github.cysin.sslsockspro.engine

import android.content.Context
import android.net.ConnectivityManager
import android.os.Process
import android.system.OsConstants
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket

/** Identifies the app that owns a loopback TCP connection. Android answers
 * only for the active VPN app and only for UIDs that VPN covers, so internal
 * endpoints admit this app and refuse every other local client. */
class LoopbackOwner(context: Context) {
    private val manager = context.getSystemService(ConnectivityManager::class.java)

    /** [peer] and [local] are the accepted socket's remote and local ends. */
    fun owned(peer: InetSocketAddress, local: InetSocketAddress): Boolean = runCatching {
        // The connecting app's local end is our peer.
        manager.getConnectionOwnerUid(OsConstants.IPPROTO_TCP, peer, local) == Process.myUid()
    }.getOrDefault(false)

    /** Whether this Android build attributes this app's own loopback
     * connections. If not, the guard cannot be enforced and is not used. */
    fun available(): Boolean = runCatching {
        val loopback = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
        ServerSocket(0, 1, loopback).use { server ->
            Socket(loopback, server.localPort).use { client ->
                server.accept().use { accepted ->
                    owned(accepted.remoteSocketAddress as InetSocketAddress, accepted.localSocketAddress as InetSocketAddress)
                }
            }
        }
    }.getOrDefault(false)
}
