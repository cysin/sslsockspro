package io.github.cysin.sslsockspro.config

import java.net.InetAddress
import java.util.Locale

class ConfigException(message: String) : IllegalArgumentException(message)

data class Endpoint(val host: String, val port: Int) {
    override fun toString(): String = if (host.contains(':')) "[$host]:$port" else "$host:$port"

    companion object {
        fun parse(value: String, listener: Boolean = false): Endpoint {
            val text = value.trim()
            val match = if (text.startsWith('[')) Regex("^\\[([^]]+)]:(\\d{1,5})$").matchEntire(text)
                else Regex("^([^\\s:]+):(\\d{1,5})$").matchEntire(text)
            val endpoint = if (match != null) Endpoint(match.groupValues[1], match.groupValues[2].toInt())
                else if (listener && text.all(Char::isDigit) && text.isNotEmpty()) Endpoint("127.0.0.1", text.toIntOrNull() ?: 0)
                else throw ConfigException("Use host:port or [IPv6]:port")
            if (endpoint.port !in 1..65535) throw ConfigException("Port must be between 1 and 65535")
            if (listener && (endpoint.host !in setOf("127.0.0.1", "::1", "localhost") || endpoint.port < 1024))
                throw ConfigException("Local listeners must use loopback and a port between 1024 and 65535")
            return endpoint
        }
    }
}

data class ConfigLine(val number: Int, val raw: String, val section: String?, val key: String? = null, val value: String? = null)

class StunnelDocument private constructor(val lines: List<ConfigLine>) {
    val sections: List<String> = lines.mapNotNull { line ->
        if (line.key == null && SECTION.matches(line.raw.trim())) line.section else null
    }
    fun values(section: String?, key: String): List<String> = lines.filter {
        it.section == section && it.key.equals(key, true)
    }.map { it.value.orEmpty() }

    fun effective(section: String, key: String): String? = values(section, key).lastOrNull() ?: values(null, key).lastOrNull()
    fun listener(section: String): Endpoint = Endpoint.parse(effective(section, "accept") ?: throw ConfigException("[$section] needs accept"), true)
    fun remotes(section: String): List<Endpoint> = values(section, "connect").map(Endpoint::parse)
    fun credentialReferences(): List<String> = lines.filter { it.key in FILE_OPTIONS }.mapNotNull { it.value }.distinct()

    /** Edit one scalar without rewriting unrelated options, comments, or
     * repeated socket/connection directives from an imported configuration. */
    fun updated(section: String, key: String, value: String): String {
        require(section in sections && KEY.matches(key) && value.none { it in "\r\n\u0000" })
        val normalized = key.lowercase(Locale.ROOT)
        val found = lines.indexOfLast { it.section == section && it.key == normalized }
        if (found >= 0) return lines.mapIndexed { index, line ->
            if (index == found) "$key = $value" else line.raw
        }.joinToString("\n") + "\n"
        val start = lines.indexOfFirst { it.section == section }
        return lines.flatMapIndexed { index, line ->
            if (index == start) listOf(line.raw, "$key = $value") else listOf(line.raw)
        }.joinToString("\n") + "\n"
    }

    fun validate() {
        if (sections.isEmpty()) throw ConfigException("Add at least one [tunnel] section")
        if (sections.toSet().size != sections.size) throw ConfigException("Tunnel section names must be unique")
        val listeners = mutableSetOf<Endpoint>()
        for (line in lines) {
            if (line.key in UNSAFE_OPTIONS || (line.key == "transparent" && line.value != "none"))
                throw ConfigException("Line ${line.number}: ${line.key} is unavailable in Android profiles")
            if (line.key == "transport" && !line.value.equals("tcp", true))
                throw ConfigException("Line ${line.number}: stunnel must use TCP transport")
            if (line.key == "sslversion" && !line.value.equals("TLSv1.3", true))
                throw ConfigException("Line ${line.number}: sslVersion cannot override the TLS 1.3 minimum")
            if (line.key == "securitylevel" && (line.value?.toIntOrNull() ?: -1) < 2)
                throw ConfigException("Line ${line.number}: securityLevel must be at least 2")
        }
        for (section in sections) {
            if (!effective(section, "client").equals("yes", true)) throw ConfigException("[$section] must use client = yes")
            if (!effective(section, "verifychain").equals("yes", true)) throw ConfigException("[$section] needs verifyChain = yes")
            if (effective(section, "checkhost").isNullOrBlank() && effective(section, "checkip").isNullOrBlank())
                throw ConfigException("[$section] needs checkHost or checkIP to verify the server's identity")
            if (!effective(section, "sslversionmin").equals("TLSv1.3", true)) throw ConfigException("[$section] needs sslVersionMin = TLSv1.3")
            if (effective(section, "cafile").isNullOrBlank()) throw ConfigException("[$section] needs a trusted CAfile")
            if (effective(section, "cert").isNullOrBlank() || effective(section, "key").isNullOrBlank())
                throw ConfigException("[$section] needs a client certificate and private key")
            if (!listeners.add(listener(section))) throw ConfigException("Local listener ports must be unique")
            if (remotes(section).isEmpty()) throw ConfigException("[$section] needs connect = server:port")
        }
    }

    /** [resolvedHosts] maps gateway names to addresses in preference order;
     * every address becomes a `connect` line so stunnel can fail over. */
    fun renderRuntime(runtimeDirectory: String, credentialPath: (String) -> String, resolvedHosts: Map<String, List<String>> = emptyMap()): String {
        validate()
        val output = StringBuilder("foreground = yes\nsyslog = no\ndebug = warning\npid = $runtimeDirectory/stunnel.pid\noutput = $runtimeDirectory/stunnel.log\n")
        for (line in lines) {
            when {
                line.key in MANAGED_OPTIONS || line.key in APP_OPTIONS -> Unit
                line.key in FILE_OPTIONS -> output.append(line.key).append(" = ").append(credentialPath(line.value.orEmpty())).append('\n')
                line.key == "connect" -> {
                    val endpoint = Endpoint.parse(line.value.orEmpty())
                    for (address in resolvedHosts[endpoint.host] ?: listOf(endpoint.host))
                        output.append("connect = ").append(endpoint.copy(host = address)).append('\n')
                }
                line.key == "accept" -> output.append("accept = ").append(Endpoint.parse(line.value.orEmpty(), true)).append('\n')
                else -> output.append(line.raw).append('\n')
            }
        }
        return output.toString()
    }

    companion object {
        private val SECTION = Regex("^\\[([^]\\r\\n]+)]\\s*$")
        private val KEY = Regex("^[a-zA-Z][a-zA-Z0-9]*$")
        val FILE_OPTIONS = setOf("cafile", "cert", "key", "crlfile")
        private val MANAGED_OPTIONS = setOf("foreground", "syslog", "debug", "pid", "output", "log")
        private val APP_OPTIONS = setOf("remark", "ovpn_profile", "ovpn_run")
        private val UNSAFE_OPTIONS = setOf("exec", "execargs", "chroot", "setuid", "setgid", "engine",
            "engineid", "enginenum", "enginectrl", "enginedefault", "provider", "providerparameter",
            "setenv", "config", "include", "rndfile", "egd", "capath", "castore", "caengine",
            "crlpath", "pty", "ocspaia", "ocsp", "sessiond", "ident", "redirect", "psksecrets",
            "pskidentity", "protocol", "protocolhost", "protocolusername", "protocolpassword",
            "protocolauthentication", "protocoldomain", "protocolheader", "verify")

        fun parse(text: String): StunnelDocument {
            if (text.toByteArray().size > 256 * 1024 || text.contains('\u0000')) throw ConfigException("Configuration is too large or contains NUL bytes")
            var section: String? = null
            val lines = text.replace("\r\n", "\n").lineSequence().mapIndexed { index, raw ->
                val trimmed = raw.trim()
                val heading = SECTION.matchEntire(trimmed)
                when {
                    heading != null -> {
                        section = heading.groupValues[1].trim()
                        if (section.isNullOrBlank()) throw ConfigException("Line ${index + 1}: empty section name")
                        ConfigLine(index + 1, raw, section)
                    }
                    trimmed.isEmpty() || trimmed.startsWith('#') || trimmed.startsWith(';') -> ConfigLine(index + 1, raw, section)
                    trimmed.contains('=') -> {
                        val key = trimmed.substringBefore('=').trim().lowercase(Locale.ROOT)
                        if (!KEY.matches(key) && key !in APP_OPTIONS) throw ConfigException("Line ${index + 1}: invalid option name")
                        ConfigLine(index + 1, raw, section, key, trimmed.substringAfter('=').trim())
                    }
                    else -> throw ConfigException("Line ${index + 1}: expected option = value")
                }
            }.toList()
            return StunnelDocument(lines)
        }

        fun template(host: String = "SERVER_IP", port: Int = 9983): String = """
            client = yes
            sslVersionMin = TLSv1.3
            verifyChain = yes
            checkHost = stunnel-server.internal
            CAfile = server-ca.crt
            cert = client.pem
            key = client.pem
            sni =
            sessionResume = no
            options = NO_TICKET
            options = NO_COMPRESSION
            TIMEOUTconnect = 15
            TIMEOUTbusy = 300
            TIMEOUTidle = 43200
            TIMEOUTclose = 60
            socket = l:TCP_NODELAY=1
            socket = r:TCP_NODELAY=1
            socket = l:SO_KEEPALIVE=1
            socket = r:SO_KEEPALIVE=1

            [proxy]
            accept = 127.0.0.1:33009
            connect = $host:$port
        """.trimIndent() + "\n"
    }
}
