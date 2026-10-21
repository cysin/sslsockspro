package io.github.cysin.sslsockspro.service

import io.github.cysin.sslsockspro.config.GatewayPlan
import io.github.cysin.sslsockspro.model.AppSettings
import io.github.cysin.sslsockspro.model.ConnectionStatus
import io.github.cysin.sslsockspro.model.TunnelProfile

/** A physical (non-VPN) network as seen when it was selected. [key] is the
 * platform network handle; [signature] changes with routing-relevant state. */
data class NetworkSnapshot(
    val key: Any,
    val signature: Int,
    val captivePortal: Boolean = false,
    val strictPrivateDns: Boolean = false,
)

/** Android operations driven by [TunnelController]. ConnectionService
 * implements them; JVM tests substitute a recording fake. Methods are called
 * on the controller's thread; suspending ones move blocking work elsewhere. */
interface TunnelPlatform {
    val alwaysOn: Boolean
    val tunOpen: Boolean
    val engineBound: Boolean
    val engineReady: Boolean
    var status: ConnectionStatus

    fun now(): Long
    fun vpnPermissionMissing(): Boolean
    suspend fun settings(): AppSettings
    suspend fun select(profileId: String)
    suspend fun profile(id: String): TunnelProfile?
    suspend fun validate(profile: TunnelProfile)

    fun physicalNetwork(): NetworkSnapshot?
    /** Gateway sockets created from now on bind to [network]. */
    fun bindSocketsTo(network: NetworkSnapshot?)
    /** Advertise [network] as the VPN's underlying network. */
    fun advertise(network: NetworkSnapshot)
    suspend fun resolveGateways(profile: TunnelProfile, network: NetworkSnapshot): GatewayPlan

    /** Opens a TUN that blocks routed traffic until the engine is ready. */
    fun establishBlocking(profile: TunnelProfile)
    fun closeTun()

    /** Begins binding the worker; readiness arrives as engineConnected(). */
    fun bindEngine(): Boolean
    fun startEngine(profile: TunnelProfile, session: String, gateways: GatewayPlan)
    fun stopEngine(session: String)
    /** True when the worker confirmed cleanup or no worker is connected. */
    suspend fun stopEngineAndWait(session: String): Boolean
    fun unbindEngine()
    fun engineNetworkChanged(session: String, sameNetwork: Boolean)

    fun log(message: String)
    fun notify(message: String)
    /** Leave the foreground and stop the owner service. */
    fun stopService()
}
