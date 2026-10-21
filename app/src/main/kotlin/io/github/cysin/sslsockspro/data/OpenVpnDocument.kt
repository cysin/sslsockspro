package io.github.cysin.sslsockspro.data

import io.github.cysin.sslsockspro.config.Endpoint
import java.util.Locale

/** Preserves inline credentials and connection blocks. The application owns
 * the management socket, TUN interface, and executable lifecycle. */
object OpenVpnDocument {
    /** The authenticated local relay that carries OpenVPN's TCP connection
     * through stunnel. [authFile] holds the relay's username and password. */
    data class HttpProxyRoute(val endpoint: Endpoint, val authFile: String)

    data class Line(val raw: String, val key: String? = null, val arguments: List<String> = emptyList())
    private val forbidden = setOf("up", "down", "route-up", "route-pre-down", "ipchange", "tls-verify",
        "auth-user-pass-verify", "client-connect", "client-disconnect", "plugin", "script-security",
        "management", "management-client", "management-external-key", "management-client-auth",
        "log", "log-append", "status", "writepid", "daemon", "chroot", "user", "group", "cd", "config",
        "secret", "server", "server-bridge", "tls-server", "mode", "tls-export-cert", "askpass",
        "http-proxy", "socks-proxy", "http-proxy-user-pass", "http-proxy-override", "providers", "engine",
        "pkcs11-providers", "replay-persist", "tmp-dir", "tls-crypt-v2-verify", "learn-address", "iproute",
        // Sends the MAC address, kernel version and UV_ variables to the server.
        "push-peer-info")
    private val owned = setOf("dev", "dev-type", "route-noexec", "ifconfig-noexec", "persist-tun",
        "management-hold", "management-query-passwords", "management-signal", "verb", "mute",
        "suppress-timestamps", "auth-nocache", "auth-retry")
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

    /** Without tls-crypt, OpenVPN's TLS handshake is visible on the network;
     * TLS 1.3 is then required so the client certificate stays encrypted. */
    private fun hidesCertificate(parsed: List<Line>) =
        parsed.any { it.key in setOf("tls-crypt", "tls-crypt-v2") || it.raw.trim() in setOf("<tls-crypt>", "<tls-crypt-v2>") }

    fun validate(config: String) {
        val parsed = lines(config)
        val hidden = hidesCertificate(parsed)
        for ((index, line) in parsed.withIndex()) checkOption(index + 1, line.key ?: continue, line.arguments, hidden)
        require(remotes(parsed).isNotEmpty()) { "OpenVPN profile needs a remote server" }
        require(parsed.any { it.key in setOf("ca", "pkcs12", "peer-fingerprint") || it.raw.trim() in setOf("<ca>", "<pkcs12>", "<peer-fingerprint>") }) {
            "OpenVPN needs a CA, PKCS#12 identity, or pinned peer fingerprint"
        }
    }

    private fun checkOption(number: Int, key: String, arguments: List<String>, hidden: Boolean, nested: Boolean = false) {
        require(key !in forbidden) { "OpenVPN line $number: $key is unavailable in Android profiles" }
        require(!key.startsWith("management-") || key in owned) { "The app owns OpenVPN management options" }
        require(!nested || key !in owned) { "OpenVPN line $number: the app manages $key" }
        // "setenv opt X" makes OpenVPN apply X; validate X like any other line.
        if (key == "setenv" && arguments.firstOrNull() == "opt") {
            require(!nested && arguments.size >= 2) { "OpenVPN line $number: invalid setenv opt" }
            checkOption(number, arguments[1].removePrefix("--").lowercase(Locale.ROOT), arguments.drop(2), hidden, nested = true)
            return
        }
        if (key == "setenv" || key == "setenv-safe") require(arguments.firstOrNull()?.uppercase(Locale.ROOT)?.let { name ->
            listOf("SSP_", "LD_", "OPENSSL_", "UV_", "IV_").any(name::startsWith)
        } != true) { "OpenVPN cannot set protection, provider or peer-information variables" }
        require(key != "dev" || arguments.firstOrNull()?.startsWith("tap") != true) { "Android VPN requires a TUN profile; TAP is unsupported" }
        require(key != "dev-type" || arguments.firstOrNull() == "tun") { "Android VPN supports dev-type tun only" }
        require(key !in setOf("compress", "comp-lzo") || arguments.firstOrNull() in setOf("no", "stub", "stub-v2")) { "VPN compression is disabled for privacy and safety" }
        require(key != "allow-compression" || arguments.firstOrNull() == "no") { "VPN compression must be disabled" }
        require(key != "proto" || arguments.firstOrNull() in setOf("udp", "udp4", "udp6", "tcp", "tcp-client", "tcp4-client", "tcp6-client")) { "Unsupported OpenVPN client protocol" }
        require(key != "remote-cert-tls" || arguments == listOf("server")) { "OpenVPN must verify a server certificate" }
        if (key == "tls-version-min" || key == "tls-version-max") {
            val allowed = if (hidden) setOf("1.2", "1.3") else setOf("1.3")
            require(arguments.firstOrNull() in allowed && (key == "tls-version-max" || arguments.size == 1)) {
                if (hidden) "OpenVPN requires TLS 1.2 or later"
                else "Without tls-crypt, OpenVPN must use TLS 1.3 so the client certificate is encrypted. Add tls-crypt or use a TLS 1.3 server."
            }
        }
        require(key != "crl-verify" || arguments.size == 1) { "Directory CRLs are unsupported; import a CRL file" }
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
                proxy: HttpProxyRoute?, resolvedHosts: Map<String, List<String>> = emptyMap(), externalKey: Boolean = false): String {
        validate(config)
        val parsed = lines(config)
        val result = StringBuilder()
        // pull-filter uses the first matching rule, so the app's rules precede
        // any rules in the imported profile.
        result.append("pull-filter reject \"http-proxy\"\n")
        // Connection blocks inherit defaults at parse time, so the proxy must
        // be configured before the first block, not appended afterward.
        if (proxy != null) result.append("proto tcp-client\nhttp-proxy ").append(quoted(proxy.endpoint.host)).append(' ')
            .append(proxy.endpoint.port).append(' ').append(quoted(proxy.authFile)).append(" basic\n")
        var connectionBlock = false
        var keyBlock = false
        for (line in parsed) {
            val key = line.key
            when (line.raw.trim()) { "<connection>" -> connectionBlock = true; "</connection>" -> connectionBlock = false }
            // With a Keystore key, no private key material may reach OpenVPN.
            if (externalKey && line.raw.trim() in setOf("<key>", "<pkcs12>")) { keyBlock = true; continue }
            if (keyBlock) { if (line.raw.trim() in setOf("</key>", "</pkcs12>")) keyBlock = false; continue }
            when {
                externalKey && key in setOf("key", "pkcs12") -> Unit
                key in owned || (proxy != null && key == "proto") -> Unit
                key in fileOptions && line.arguments.isNotEmpty() -> {
                    result.append(key).append(' ').append(quoted(credentials(line.arguments[0])))
                    line.arguments.drop(1).forEach { result.append(' ').append(quoted(it)) }
                    result.append('\n')
                }
                key == "remote" -> {
                    // Top-level remotes fail over in order. A connection block
                    // holds one remote, so it keeps the preferred address.
                    val addresses = resolvedHosts[line.arguments[0].removeSurrounding("[", "]")] ?: listOf(line.arguments[0])
                    for (address in if (connectionBlock) addresses.take(1) else addresses) {
                        result.append("remote ").append(quoted(address))
                        line.arguments.drop(1).take(if (proxy == null) 2 else 1).forEach { result.append(' ').append(quoted(it)) }
                        if (proxy != null) result.append(" tcp-client")
                        result.append('\n')
                    }
                }
                else -> result.append(line.raw).append('\n')
            }
        }
        // auth-retry interact lets a server's dynamic (CRV1) challenge ask for
        // credentials again; plain rejections still end the connection.
        result.append("\ndev tun\ndev-type tun\nmanagement ").append(quoted(managementSocket))
            .append(" unix\nmanagement-query-passwords\nmanagement-hold\nmanagement-signal\nauth-retry interact\nverb 3\nallow-compression no\n")
        // The app signs with the Keystore key; OpenVPN sends the message and
        // its hash algorithm so standard Keystore signatures apply.
        if (externalKey) result.append("management-external-key pkcs1 pss digest\n")
        if (parsed.none { it.key == "remote-cert-tls" }) result.append("remote-cert-tls server\n")
        if (parsed.none { it.key == "tls-version-min" }) result.append(if (hidesCertificate(parsed)) "tls-version-min 1.2\n" else "tls-version-min 1.3\n")
        return result.toString()
    }

    fun quoted(value: String): String {
        require(value.none { it == '\n' || it == '\r' || it == '\u0000' }) { "Invalid OpenVPN value" }
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\""
    }
}
