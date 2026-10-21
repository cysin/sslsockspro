package io.github.cysin.sslsockspro.data

import io.github.cysin.sslsockspro.model.ConnectionMode
import io.github.cysin.sslsockspro.model.DnsMode
import io.github.cysin.sslsockspro.model.ProxyKind
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.util.io.pem.PemReader
import java.io.StringReader
import java.security.MessageDigest
import java.util.Base64

/** Optional operator signature for client packages. The operator signs a
 * manifest of every file's SHA-256 with an Ed25519 key; the app shows the
 * key's fingerprint so the user can compare it with one received separately.
 * A checksum file inside a package proves nothing on its own about origin. */
object PackageManifest {
    const val MANIFEST = "ssp-manifest.json"
    const val SIGNATURE = "ssp-manifest.sig"
    const val OPERATOR_KEY = "ssp-operator.pub"
    val NAMES = setOf(MANIFEST, SIGNATURE, OPERATOR_KEY)

    @Serializable
    data class ProfileHint(
        val config: String,
        val name: String? = null,
        val mode: ConnectionMode? = null,
        val proxyKind: ProxyKind? = null,
        val section: String? = null,
        val dnsMode: DnsMode? = null,
    )

    @Serializable
    data class Manifest(val format: Int, val files: Map<String, String>, val profiles: List<ProfileHint> = emptyList())

    data class Verified(val fingerprint: String, val manifest: Manifest)

    private val codec = Json { ignoreUnknownKeys = false }

    /** Checks a signed manifest against [files], which must not contain the
     * manifest's own files. Returns null for an unsigned package. */
    fun verify(files: Map<String, ByteArray>, manifest: ByteArray?, signature: ByteArray?, operatorKey: ByteArray?): Verified? {
        if (manifest == null) {
            require(signature == null && operatorKey == null) { "Package signature files are incomplete" }
            return null
        }
        require(signature != null && operatorKey != null) { "The package manifest is not signed" }
        val keyInfo = runCatching {
            val pem = PemReader(StringReader(operatorKey.toString(Charsets.US_ASCII))).use { it.readPemObject() }
            require(pem.type == "PUBLIC KEY")
            SubjectPublicKeyInfo.getInstance(pem.content)
        }.getOrElse { throw IllegalArgumentException("The operator key must be an Ed25519 public key in PEM form") }
        require(keyInfo.algorithm.algorithm == EdECObjectIdentifiers.id_Ed25519) { "The operator key must be an Ed25519 public key" }
        val signatureBytes = runCatching { Base64.getMimeDecoder().decode(signature.toString(Charsets.US_ASCII).trim()) }.getOrNull()
        val verifier = Ed25519Signer().apply {
            init(false, Ed25519PublicKeyParameters(keyInfo.publicKeyData.bytes))
            update(manifest, 0, manifest.size)
        }
        require(signatureBytes != null && signatureBytes.size == 64 && verifier.verifySignature(signatureBytes)) {
            "The package signature does not match its manifest"
        }
        val parsed = codec.decodeFromString<Manifest>(manifest.toString(Charsets.UTF_8))
        require(parsed.format == 1) { "Unsupported package manifest format" }
        require(parsed.files.keys == files.keys) { "Package files do not match its signed manifest" }
        for ((name, data) in files) require(sha256(data).equals(parsed.files.getValue(name), ignoreCase = true)) { "Package file $name does not match its signed manifest" }
        return Verified(sha256(keyInfo.encoded).uppercase(), parsed)
    }

    fun sha256(data: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(data).joinToString("") { "%02x".format(it) }

    /** Groups of four for reading aloud or comparing on screen. */
    fun display(fingerprint: String): String = fingerprint.chunked(4).joinToString(" ")
}
