package io.github.cysin.sslsockspro.engine

import io.github.cysin.sslsockspro.model.ConnectionMode

/** Worker-to-owner event codes. The worker reports what happened; wording
 * shown to the user is produced only by [message] in the owner process. */
object EngineEvent {
    const val LOG = 1
    const val LISTENING = 2
    const val CONNECTED = 3
    const val RECONNECTING = 4

    // Transient failures: the owner keeps the blocking TUN and retries.
    const val ENGINE_STOPPED = 10
    const val HEALTH_FAILED = 11
    const val DIAGNOSTICS_FAILED = 12
    const val START_FAILED = 13
    const val OPENVPN_CONTROL_LOST = 14
    const val OPENVPN_ENDED = 15

    // Permanent failures: the profile needs an edit, so no retry loop.
    const val CONFIG_ERROR = 20
    const val AUTH_REJECTED = 21
    const val CREDENTIALS_REQUIRED = 22
    const val OPENVPN_FATAL = 23

    fun isFailure(code: Int) = code >= ENGINE_STOPPED
    fun isPermanent(code: Int) = code >= CONFIG_ERROR

    fun message(code: Int, detail: String, mode: ConnectionMode?): String = when (code) {
        LOG -> detail
        LISTENING -> "Local TLS listeners ready. Server TLS is verified when an app connects. Phone-wide routing is off."
        CONNECTED -> if (mode == ConnectionMode.OPENVPN) "OpenVPN connected; traffic is tunneled"
            else "VPN connected: TCP and DNS tunneled; other UDP blocked"
        RECONNECTING -> "OpenVPN is reconnecting; traffic remains blocked"
        ENGINE_STOPPED -> "Native network engine stopped; traffic remains blocked"
        HEALTH_FAILED -> "Tunnel health check failed; reconnecting without direct DNS or network fallback"
        DIAGNOSTICS_FAILED -> "Native diagnostics stopped unexpectedly; reconnecting with traffic blocked"
        START_FAILED -> detail.ifBlank { "Native engine initialization failed" }
        OPENVPN_CONTROL_LOST -> "OpenVPN control connection stopped"
        OPENVPN_ENDED -> "OpenVPN connection ended"
        CONFIG_ERROR -> detail.ifBlank { "The profile configuration was rejected" }
        AUTH_REJECTED -> "OpenVPN authentication was rejected; check the profile credentials"
        CREDENTIALS_REQUIRED -> "OpenVPN requires credentials. Add the username/password or key passphrase in the profile editor."
        OPENVPN_FATAL -> "OpenVPN could not establish the connection; check configuration and certificates"
        else -> detail.ifBlank { "The native engine reported an unknown event" }
    }
}
