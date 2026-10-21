package io.github.cysin.sslsockspro.data

import io.github.cysin.sslsockspro.config.Endpoint
import io.github.cysin.sslsockspro.config.StunnelDocument
import io.github.cysin.sslsockspro.model.ConnectionMode
import io.github.cysin.sslsockspro.model.TunnelProfile

/** The servers a profile connects to directly over the physical network. */
object Gateways {
    fun endpoints(profile: TunnelProfile): List<Endpoint> = buildList {
        if (profile.mode != ConnectionMode.OPENVPN || profile.openVpnViaStunnel) {
            val document = StunnelDocument.parse(profile.config)
            document.sections.forEach { addAll(document.remotes(it)) }
        }
        if (profile.mode == ConnectionMode.OPENVPN && !profile.openVpnViaStunnel) addAll(OpenVpnDocument.remotes(profile.openVpnConfig))
    }

    /** Literal syntax only; never resolves a name. */
    fun isAddressLiteral(host: String): Boolean =
        host.contains(':') || Regex("(?:\\d{1,3}\\.){3}\\d{1,3}").matches(host)

    /** Names resolved on the current network before connecting, which reveals
     * them to that network's resolver. Numeric addresses avoid the lookup. */
    fun lookedUpNames(profile: TunnelProfile): List<String> =
        runCatching { endpoints(profile) }.getOrDefault(emptyList()).map { it.host }.filterNot(::isAddressLiteral).distinct()
}
