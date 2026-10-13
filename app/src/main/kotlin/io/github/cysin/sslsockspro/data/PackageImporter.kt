package io.github.cysin.sslsockspro.data

import io.github.cysin.sslsockspro.config.StunnelDocument
import io.github.cysin.sslsockspro.model.ConnectionMode
import io.github.cysin.sslsockspro.model.ProxyKind
import io.github.cysin.sslsockspro.model.TunnelProfile
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.FilterInputStream
import java.security.MessageDigest
import java.util.Base64
import java.util.zip.GZIPInputStream
import java.util.zip.ZipInputStream

object PackageImporter {
    const val MAX_TOTAL = 16 * 1024 * 1024
    const val MAX_FILE = 4 * 1024 * 1024
    fun safeName(name: String): Boolean = name.isNotBlank() && name.length <= 160 && name !in setOf(".", "..") &&
        name.none { it == '/' || it == '\\' || it.code < 32 || it.code == 127 }

    fun boundedRead(stream: InputStream, maximum: Int): ByteArray {
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(8192)
        while (true) {
            val count = stream.read(buffer)
            if (count < 0) break
            require(output.size() + count <= maximum) { "Import exceeds the permitted size" }
            output.write(buffer, 0, count)
        }
        return output.toByteArray()
    }

    fun entries(bytes: ByteArray, filename: String): Map<String, ByteArray> {
        require(bytes.size <= MAX_TOTAL) { "Package exceeds 16 MiB" }
        val files = linkedMapOf<String, ByteArray>()
        val paths = mutableSetOf<String>()
        var total = 0
        fun add(path: String, data: ByteArray) {
            val parts = path.split('/')
            require(!path.startsWith('/') && '\\' !in path && parts.none { it == ".." || it == "." } && paths.add(path)) { "Unsafe or duplicate archive path" }
            require(paths.size <= 128) { "Package has too many entries" }
            total += data.size
            require(total <= MAX_TOTAL) { "Expanded package exceeds 16 MiB" }
            val name = parts.last()
            require(safeName(name)) { "Invalid package filename" }
            val previous = files[name]
            require(previous == null || previous.contentEquals(data)) { "Package contains ambiguous credential filenames" }
            files[name] = data
        }
        when {
            filename.endsWith(".zip", true) -> ZipInputStream(ByteArrayInputStream(bytes)).use { zip ->
                var entries = 0
                while (true) {
                    val entry = zip.nextEntry ?: break
                    require(++entries <= 128) { "Package has too many entries" }
                    require(!entry.name.startsWith('/') && entry.name.split('/').none { it == ".." }) { "Unsafe ZIP path" }
                    if (!entry.isDirectory) add(entry.name, boundedRead(zip, MAX_FILE))
                    else require(boundedRead(zip, 0).isEmpty()) { "ZIP directory contains file data" }
                    zip.closeEntry()
                }
            }
            filename.endsWith(".tar.gz", true) || filename.endsWith(".tgz", true) || filename.endsWith(".tar", true) -> {
                val input = ByteArrayInputStream(bytes)
                val expanded = if (filename.endsWith(".tar", true)) input else GZIPInputStream(input)
                val budget = object : FilterInputStream(expanded) {
                    private var count = 0L
                    override fun read(): Int = super.read().also { if (it >= 0) { count++; require(count <= MAX_TOTAL + 1024 * 1024) { "Expanded archive exceeds its limit" } } }
                    override fun read(bytes: ByteArray, offset: Int, length: Int): Int = `in`.read(bytes, offset, length).also {
                        if (it > 0) { count += it; require(count <= MAX_TOTAL + 1024 * 1024) { "Expanded archive exceeds its limit" } }
                    }
                    override fun skip(length: Long): Long {
                        val buffer = ByteArray(8192)
                        var skipped = 0L
                        while (skipped < length) { val n = read(buffer, 0, minOf(buffer.size.toLong(), length - skipped).toInt()); if (n < 0) break; skipped += n }
                        return skipped
                    }
                }
                TarArchiveInputStream(budget).use { tar ->
                    var entries = 0
                    while (true) {
                        val entry = tar.nextEntry ?: break
                        require(++entries <= 128 && !entry.isSymbolicLink && !entry.isLink) { "Archive links and excessive entries are unsupported" }
                        require(entry.isFile || entry.isDirectory) { "Archive special files are unsupported" }
                        require(!entry.name.startsWith('/') && entry.name.split('/').none { it == ".." }) { "Unsafe TAR path" }
                        if (entry.isFile) add(entry.name, boundedRead(tar, MAX_FILE))
                    }
                }
            }
            else -> add(filename, bytes)
        }
        files.remove("SHA256SUMS")?.toString(Charsets.UTF_8)?.lineSequence()?.filter(String::isNotBlank)?.forEach { line ->
            val match = Regex("^([a-fA-F0-9]{64})  ([^/\\\\]+)$").matchEntire(line) ?: throw IllegalArgumentException("Invalid package checksum manifest")
            files[match.groupValues[2]]?.let { data ->
                val hash = MessageDigest.getInstance("SHA-256").digest(data).joinToString("") { "%02x".format(it) }
                require(hash.equals(match.groupValues[1], true)) { "Package checksum mismatch" }
            }
        }
        return files
    }

    fun profiles(files: Map<String, ByteArray>): List<TunnelProfile> {
        val configs = files.filterKeys { it.endsWith(".conf", true) }
        val vpn = files.filterKeys { it.endsWith(".ovpn", true) }
        val references = (configs.values.flatMap { StunnelDocument.parse(it.toString(Charsets.UTF_8)).credentialReferences() } +
            vpn.values.flatMap { OpenVpnDocument.credentialReferences(it.toString(Charsets.UTF_8)) }).map(Credentials::referenceName).toSet()
        val encoded = files.filterKeys { it in references || it.substringAfterLast('.', "").lowercase() in setOf("pem", "crt", "cer", "der", "key", "p12", "pfx", "crl", "auth", "txt") }
            .mapValues { Base64.getEncoder().encodeToString(it.value) }
        if (configs.isEmpty()) return vpn.map { (name, bytes) ->
            OpenVpnDocument.validate(bytes.toString(Charsets.UTF_8))
            TunnelProfile(name = name.substringBeforeLast('.'), config = "", mode = ConnectionMode.OPENVPN,
                openVpnConfig = bytes.toString(Charsets.UTF_8), files = encoded)
        }
        return configs.map { (name, bytes) ->
            val document = StunnelDocument.parse(bytes.toString(Charsets.UTF_8))
            document.validate()
            val section = document.sections.first()
            val kind = if (document.remotes(section).first().port == 9984) ProxyKind.SOCKS5 else ProxyKind.HTTP_CONNECT
            TunnelProfile(name = name.substringBeforeLast('.'), config = bytes.toString(Charsets.UTF_8),
                selectedSection = section, proxyKind = kind, files = encoded,
                openVpnConfig = vpn.values.firstOrNull()?.toString(Charsets.UTF_8).orEmpty())
        }
    }
}
