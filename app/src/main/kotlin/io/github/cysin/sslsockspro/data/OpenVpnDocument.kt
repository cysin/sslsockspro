package io.github.cysin.sslsockspro.data

import io.github.cysin.sslsockspro.config.Endpoint
import java.util.Locale

/** Preserves inline credentials and connection blocks. The application owns
 * the management socket, TUN interface, and executable lifecycle. */
object OpenVpnDocument {
    data class Line(val raw: String, val key: String? = null, val arguments: List<String> = emptyList())
    private val forbidden = setOf("up", "down", "route-up", "route-pre-down", "ipchange", "tls-verify",
        "auth-user-pass-verify", "client-connect", "client-disconnect", "plugin", "script-security",
        "management", "management-client", "management-external-key", "management-client-auth",
        "log", "log-append", "status", "writepid", "daemon", "chroot", "user", "group", "cd", "config",
        "secret", "server", "server-bridge", "tls-server", "mode", "tls-export-cert", "askpass",
        "http-proxy", "socks-proxy", "http-proxy-user-pass", "http-proxy-override", "providers", "engine",
        "pkcs11-providers", "replay-persist", "tmp-dir", "tls-crypt-v2-verify", "learn-address", "iproute")
    private val owned = setOf("dev", "dev-type", "route-noexec", "ifconfig-noexec", "persist-tun",
        "management-hold", "management-query-passwords", "management-signal", "verb", "mute",
        "suppress-timestamps", "auth-nocache", "pull-filter")
    private val fileOptions = setOf("ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2", "pkcs12",
        "crl-verify", "auth-user-pass", "extra-certs")
    private val inlineOptions = fileOptions - "crl-verify" + "peer-fingerprint"

    fun tokenize(text: String): List<String> {
        val result = mutableListOf<String>()
        val word = StringBuilder()
        var quote: Char? = null
        var escaped = false
        var started = false
        for (character in text) {
            if (escaped) { word.append(character); escaped = false; started = true; continue }
            if (character == '\\' && quote != '\'') { escaped = true; started = true; continue }
            if (quote != null) {
                if (character == quote) quote = null else word.append(character)
                continue
            }
            when {
                character == '"' || character == '\'' -> { quote = character; started = true }
                character.isWhitespace() -> if (started) { result += word.toString(); word.clear(); started = false }
                character in "#;" && !started -> break
                else -> { word.append(character); started = true }
            }
        }
        require(quote == null && !escaped) { "Unterminated OpenVPN quote or escape" }
        if (started) result += word.toString()
        return result
    }

    fun lines(config: String): List<Line> {
        require(config.toByteArray().size <= 256 * 1024 && '\u0000' !in config) { "Invalid OpenVPN configuration size or content" }
        var inline: String? = null
        var connection = false
        val lines = config.lineSequence().mapIndexed { index, raw ->
            val text = raw.trim()
            when {
                inline != null -> {
                    if (text == "</$inline>") inline = null
                    Line(raw)
                }
                text == "<connection>" -> {
                    require(!connection) { "OpenVPN line " + (index + 1) + ": nested connection block" }
                    connection = true; Line(raw)
                }
                text == "</connection>" -> {
                    require(connection) { "OpenVPN line " + (index + 1) + ": unexpected closing block" }
                    connection = false; Line(raw)
                }
                text.startsWith('<') -> {
                    val tag = text.removePrefix("<").removeSuffix(">")
                    require(text.endsWith('>') && tag in inlineOptions) { "OpenVPN line " + (index + 1) + ": unsupported inline block" }
                    inline = tag; Line(raw)
                }
                else -> {
                    val tokens = tokenize(text)
                    Line(raw, tokens.firstOrNull()?.removePrefix("--")?.lowercase(Locale.ROOT), tokens.drop(1))
                }
            }
        }.toList()
        require(inline == null && !connection) { "OpenVPN inline and connection blocks must be complete" }
        return lines
    }

    fun validate(config: String) {
        val parsed = lines(config)
        for ((index, line) in parsed.withIndex()) {
            val key = line.key ?: continue
            require(key !in forbidden) { "OpenVPN line " + (index + 1) + ": $key is unavailable in Android profiles" }
            require(!key.startsWith("management-") || key in owned) { "The app owns OpenVPN management options" }
            if (key == "setenv" || key == "setenv-safe") require(line.arguments.firstOrNull()?.let {
                it.startsWith("SSP_") || it.startsWith("LD_") || it.startsWith("OPENSSL_")
            } != true) { "OpenVPN cannot override native protection or provider environments" }
            require(key != "dev" || line.arguments.firstOrNull()?.startsWith("tap") != true) { "Android VPN requires a TUN profile; TAP is unsupported" }
            require(key != "dev-type" || line.arguments.firstOrNull() == "tun") { "Android VPN supports dev-type tun only" }
            require(key !in setOf("compress", "comp-lzo") || line.arguments.firstOrNull() in setOf("no", "stub", "stub-v2")) { "VPN compression is disabled for privacy and safety" }
            require(key != "allow-compression" || line.arguments.firstOrNull() == "no") { "VPN compression must be disabled" }
            require(key != "proto" || line.arguments.firstOrNull() in setOf("udp", "udp4", "udp6", "tcp", "tcp-client", "tcp4-client", "tcp6-client")) { "Unsupported OpenVPN client protocol" }
            require(key != "remote-cert-tls" || line.arguments == listOf("server")) { "OpenVPN must verify a server certificate" }
            require(key != "tls-version-min" || line.arguments.firstOrNull() in setOf("1.2", "1.3")) { "OpenVPN requires TLS 1.2 or later" }
            require(key != "crl-verify" || line.arguments.size == 1) { "Directory CRLs are unsupported; import a CRL file" }
        }
        require(remotes(parsed).isNotEmpty()) { "OpenVPN profile needs a remote server" }
        require(parsed.any { it.key in setOf("ca", "pkcs12", "peer-fingerprint") || it.raw.trim() in setOf("<ca>", "<pkcs12>", "<peer-fingerprint>") }) {
            "OpenVPN needs a CA, PKCS#12 identity, or pinned peer fingerprint"
        }
    }

    fun remotes(config: String): List<Endpoint> = remotes(lines(config))
    private fun remotes(parsed: List<Line>): List<Endpoint> = parsed.filter { it.key == "remote" }.map { line ->
        require(line.arguments.size in 1..3) { "Invalid OpenVPN remote" }
        val host = line.arguments[0].removeSurrounding("[", "]")
        require(host.isNotBlank() && host.none { it.isWhitespace() || it in "'\"/\\" }) { "Invalid OpenVPN gateway hostname" }
        Endpoint(host, line.arguments.getOrNull(1)?.toIntOrNull() ?: 1194).also {
            require(it.port in 1..65535) { "Invalid OpenVPN gateway port" }
            require(line.arguments.getOrNull(1) == null || line.arguments[1].toIntOrNull() != null) { "OpenVPN remote port must be numeric" }
        }
    }

    fun credentialReferences(config: String): List<String> = lines(config).filter { it.key in fileOptions }
        .mapNotNull { it.arguments.firstOrNull() }.distinct()

    fun runtime(config: String, credentials: (String) -> String, managementSocket: String,
                proxy: Pair<String, Endpoint>?, resolvedHosts: Map<String, String> = emptyMap()): String {
        validate(config)
        val parsed = lines(config)
        val result = StringBuilder()
        // Connection blocks inherit defaults at parse time, so the proxy must
        // be configured before the first block, not appended afterward.
        if (proxy != null) result.append("proto tcp-client\n").append(proxy.first).append(' ')
            .append(quoted(proxy.second.host)).append(' ').append(proxy.second.port).append('\n')
        for (line in parsed) {
            val key = line.key
            when {
                key in owned || (proxy != null && key == "proto") -> Unit
                key in fileOptions && line.arguments.isNotEmpty() -> {
                    result.append(key).append(' ').append(quoted(credentials(line.arguments[0])))
                    line.arguments.drop(1).forEach { result.append(' ').append(quoted(it)) }
                    result.append('\n')
                }
                key == "remote" -> {
                    result.append("remote ").append(quoted(resolvedHosts[line.arguments[0].removeSurrounding("[", "]")] ?: line.arguments[0]))
                    line.arguments.drop(1).take(if (proxy == null) 2 else 1).forEach { result.append(' ').append(quoted(it)) }
                    if (proxy != null) result.append(" tcp-client")
                    result.append('\n')
                }
                else -> result.append(line.raw).append('\n')
            }
        }
        result.append("\ndev tun\ndev-type tun\nmanagement ").append(quoted(managementSocket))
            .append(" unix\nmanagement-query-passwords\nmanagement-hold\nmanagement-signal\nverb 3\nallow-compression no\n")
        if (parsed.none { it.key == "remote-cert-tls" }) result.append("remote-cert-tls server\n")
        if (parsed.none { it.key == "tls-version-min" }) result.append("tls-version-min 1.2\n")
        result.append("pull-filter reject \"http-proxy\"\n")
        return result.toString()
    }

    fun quoted(value: String): String {
        require(value.none { it == '\n' || it == '\r' || it == '\u0000' }) { "Invalid OpenVPN value" }
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\""
    }
}
