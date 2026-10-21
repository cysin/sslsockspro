package io.github.cysin.sslsockspro.ui

internal data class NetworkTransport(val label: String, val validated: Boolean)

/** An active VPN advertises its underlying transport. Prefer that over an
 * unrelated validated mobile network that Android keeps available. */
internal fun currentNetworkTransport(active: String?, available: List<NetworkTransport>): String? =
    active ?: (available.firstOrNull { it.validated } ?: available.firstOrNull())?.label
