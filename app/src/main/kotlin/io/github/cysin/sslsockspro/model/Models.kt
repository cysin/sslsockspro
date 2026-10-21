package io.github.cysin.sslsockspro.model

import kotlinx.serialization.Serializable
import java.util.UUID

@Serializable
enum class ConnectionMode { LOCAL_PROXY, PROXY_VPN, OPENVPN }

@Serializable
enum class ProxyKind { HTTP_CONNECT, SOCKS5 }

/** DOH sends app DNS as DNS-over-HTTPS through the tunnel. PROXY answers
 * address queries with synthetic addresses and lets the proxy resolve names. */
@Serializable
enum class DnsMode { DOH, PROXY }

@Serializable
data class TunnelProfile(
    val id: String = UUID.randomUUID().toString(),
    val name: String,
    val config: String,
    val mode: ConnectionMode = ConnectionMode.PROXY_VPN,
    val proxyKind: ProxyKind = ProxyKind.HTTP_CONNECT,
    val selectedSection: String = "",
    val files: Map<String, String> = emptyMap(),
    val openVpnConfig: String = "",
    val openVpnViaStunnel: Boolean = false,
    val openVpnUsername: String = "",
    val openVpnPassword: String = "",
    val openVpnKeyPassphrase: String = "",
    val includedApps: List<String> = emptyList(),
    val dnsEndpoint: String = "https://cloudflare-dns.com/dns-query",
    val proxyIpv6: Boolean = false,
    val suppressServiceBindings: Boolean = true,
    val dnsMode: DnsMode = DnsMode.DOH,
    /** Optional credentials for the HTTP CONNECT or SOCKS5 backend. */
    val proxyUsername: String = "",
    val proxyPassword: String = "",
    /** Android Keystore alias of a non-exportable OpenVPN client key. */
    val openVpnKeyAlias: String = "",
    /** SHA-256 fingerprint of the operator key that signed the imported package. */
    val operatorKeyFingerprint: String = "",
    val modifiedAt: Long = System.currentTimeMillis(),
) {
    fun backendCredentials(): Pair<String, String>? = proxyUsername.takeIf { it.isNotEmpty() }?.let { it to proxyPassword }
}

@Serializable
enum class ConnectionStage { IDLE, VALIDATING, CONNECTING, LISTENING, CONNECTED, RECONNECTING, STOPPING, ERROR }

@Serializable
data class ConnectionStatus(
    val stage: ConnectionStage = ConnectionStage.IDLE,
    val profileId: String? = null,
    val message: String = "Disconnected",
    val startedAt: Long = 0,
    val bytesSent: Long = 0,
    val bytesReceived: Long = 0,
    val running: Boolean = false,
    val vpnActive: Boolean = false,
    val alwaysOn: Boolean = false,
)

@Serializable
data class AppSettings(
    val selectedProfileId: String? = null,
    val reconnect: Boolean = true,
    val darkTheme: Boolean? = null,
    /** Start the selected local-proxy profile after the phone boots. */
    val bootStartLocalProxy: Boolean = false,
)

/** Portable snapshot: profiles and settings. Format 1 predates split storage. */
@Serializable
data class Backup(val format: Int = Backup.FORMAT, val profiles: List<TunnelProfile>, val settings: AppSettings = AppSettings()) {
    companion object { const val FORMAT = 2 }
}
