package io.github.cysin.sslsockspro.privacy

import java.util.Locale

/** Removes identifying data from diagnostics before they are stored or
 * shown: network addresses, hardware addresses, certificate subjects, email
 * addresses, private paths and configured gateway names. Synthetic in-tunnel
 * and loopback addresses stay readable because they identify no one. */
object Redactor {
    private val credential = Regex("(?i)password|passphrase|authorization|private.?key|bearer\\s|auth.?token|session.?token|cookie")
    private val path = Regex("/(?:data|home|storage|sdcard)/[^\\s]+")
    private val email = Regex("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}")
    private val hardware = Regex("\\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\\b")
    private val distinguished = Regex("(?i)\\b(CN|O|OU|L|ST|C|emailAddress|serialNumber|UID|DC|GN|SN|title|name)\\s*=\\s*[^,/\\]\\n]+")
    private val ipv4 = Regex("(?<![0-9.])(?:\\d{1,3}\\.){3}\\d{1,3}(?![0-9.])")
    private val ipv6 = Regex("(?i)(?<![0-9a-f:])[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}(?:%[\\w.]+)?(?![0-9a-f:])")
    @Volatile private var names: List<String> = emptyList()

    /** Gateway names are replaced wherever they appear in later messages. */
    fun sensitiveNames(values: Collection<String>) {
        names = values.filter { it.length >= 3 && !isAddress(it) }.map { it.lowercase(Locale.ROOT) }.distinct().sortedByDescending { it.length }
    }

    /** For stored diagnostics: credential-related lines are dropped entirely. */
    fun redact(message: String): String =
        if (credential.containsMatchIn(message)) "[credential-related diagnostic redacted]" else redactIdentifiers(message)

    /** For user-facing status text, which may legitimately mention passwords. */
    fun redactIdentifiers(message: String): String {
        var text = message.replace(path, "[private path]")
        for (name in names) text = text.replace(name, "[gateway]", ignoreCase = true)
        text = text.replace(email, "[email]")
        text = text.replace(distinguished) { "${it.groupValues[1]}=[redacted]" }
        text = text.replace(hardware, "[hardware address]")
        text = text.replace(ipv4) { if (internalIpv4(it.value)) it.value else "[address]" }
        text = text.replace(ipv6) { if (!validIpv6(it.value.substringBefore('%')) || internalIpv6(it.value)) it.value else "[address]" }
        return text
    }

    private fun isAddress(value: String) = ipv4.matches(value) || value.contains(':')

    private fun internalIpv4(value: String): Boolean {
        val parts = value.split('.').map { it.toIntOrNull() ?: return true }
        if (parts.any { it > 255 }) return true // not an address, e.g. a version string
        return parts[0] == 127 || parts.all { it == 0 } || parts[0] == 255 ||
            (parts[0] == 198 && (parts[1] == 18 || parts[1] == 19))
    }

    private fun internalIpv6(value: String): Boolean {
        val normalized = value.lowercase(Locale.ROOT)
        return normalized == "::1" || normalized == "::" || normalized.startsWith("fd00:5353:")
    }

    /** Literal syntax check only; never performs a name lookup. */
    private fun validIpv6(value: String): Boolean {
        if (value.count { it == ':' } < 2 || value.contains(":::")) return false
        val compressed = value.contains("::")
        if (compressed && value.indexOf("::") != value.lastIndexOf("::")) return false
        val groups = value.split(':').filter { it.isNotEmpty() }
        if (groups.any { it.length > 4 }) return false
        return if (compressed) groups.size <= 7 else groups.size == 8
    }
}
