package io.github.cysin.sslsockspro.data

import android.security.keystore.KeyProperties
import android.security.keystore.KeyProtection
import android.security.keystore.StrongBoxUnavailableException
import io.github.cysin.sslsockspro.config.StunnelDocument
import io.github.cysin.sslsockspro.model.TunnelProfile
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.sec.SECObjectIdentifiers
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.util.io.pem.PemObject
import org.bouncycastle.util.io.pem.PemWriter
import java.io.ByteArrayInputStream
import java.io.StringWriter
import java.security.KeyFactory
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64

/** OpenVPN client keys held by Android Keystore. Once imported the key
 * cannot be read by anyone, including this app; OpenVPN asks the app to sign
 * through its management interface. Keys are not part of portable backups. */
object KeystoreKeys {
    const val NOTE = "# The client key is held in Android Keystore."
    const val CERTIFICATE_FILE = "openvpn-client.crt"
    const val AUTHORITY_FILE = "openvpn-ca.crt"

    fun alias(profileId: String) = "sslsockspro.openvpn.$profileId"

    enum class Storage { NONE, KEYSTORE, MISSING, APP_STORAGE }

    /** Where an OpenVPN profile's client key lives, for display. */
    fun storage(profile: TunnelProfile): Storage = when {
        profile.openVpnConfig.isBlank() -> Storage.NONE
        profile.openVpnKeyAlias.isNotEmpty() -> if (present(profile.openVpnKeyAlias)) Storage.KEYSTORE else Storage.MISSING
        runCatching { OpenVpnDocument.lines(profile.openVpnConfig) }.getOrDefault(emptyList()).any {
            it.key in setOf("key", "pkcs12") || it.raw.trim() in setOf("<key>", "<pkcs12>")
        } -> Storage.APP_STORAGE
        else -> Storage.NONE
    }

    private fun store(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    fun present(alias: String): Boolean = alias.isNotEmpty() && runCatching { store().containsAlias(alias) }.getOrDefault(false)
    fun delete(alias: String) { if (alias.isNotEmpty()) runCatching { store().deleteEntry(alias) } }

    /** The client identity of an OpenVPN profile before migration. */
    class Identity(val key: PrivateKeyInfo, val chain: List<X509Certificate>, val authorities: List<X509Certificate>)

    /** Moves the OpenVPN client key of [profile] into Keystore. Returns the
     * profile unchanged when there is no supported key to move: none,
     * already moved, still encrypted without a saved passphrase, or a key
     * type Keystore cannot import (such as Ed25519). */
    fun migrate(profile: TunnelProfile): TunnelProfile {
        if (profile.openVpnConfig.isBlank() || profile.openVpnKeyAlias.isNotEmpty()) return profile
        val identity = runCatching { identity(profile) }.getOrNull() ?: return profile
        val private = runCatching { platformKey(identity.key) }.getOrNull() ?: return profile
        val alias = alias(profile.id)
        importKey(alias, private, identity.chain)
        return withoutKeyMaterial(profile, identity).copy(openVpnKeyAlias = alias, openVpnKeyPassphrase = "")
    }

    private fun platformKey(key: PrivateKeyInfo): PrivateKey? {
        val algorithm = when (key.privateKeyAlgorithm.algorithm) {
            PKCSObjectIdentifiers.rsaEncryption -> "RSA"
            X9ObjectIdentifiers.id_ecPublicKey -> "EC"
            else -> return null
        }
        return KeyFactory.getInstance(algorithm).generatePrivate(PKCS8EncodedKeySpec(key.encoded))
    }

    private fun importKey(alias: String, key: PrivateKey, chain: List<X509Certificate>) {
        val store = store()
        // P-256 always signs with SHA-256 in TLS 1.3, which StrongBox supports;
        // other keys use the TEE with every SHA-2 digest available.
        val p256 = key.algorithm == "EC" && chain.first().publicKey.encoded.let { encoded ->
            org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(encoded).algorithm.parameters?.toASN1Primitive() == SECObjectIdentifiers.secp256r1
        }
        fun protection(strongBox: Boolean) = KeyProtection.Builder(KeyProperties.PURPOSE_SIGN)
            .setDigests(*if (strongBox) arrayOf(KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256)
                else arrayOf(KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA224, KeyProperties.DIGEST_SHA256,
                    KeyProperties.DIGEST_SHA384, KeyProperties.DIGEST_SHA512))
            .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1, KeyProperties.SIGNATURE_PADDING_RSA_PSS)
            .setIsStrongBoxBacked(strongBox).build()
        val entry = KeyStore.PrivateKeyEntry(key, chain.toTypedArray())
        if (p256) {
            try { store.setEntry(alias, entry, protection(true)); return }
            catch (_: StrongBoxUnavailableException) { }
            catch (_: java.security.KeyStoreException) { }
        }
        store.setEntry(alias, entry, protection(false))
    }

    /** Finds the client key and certificates referenced by the OpenVPN
     * configuration: key/cert files, inline blocks or a PKCS#12 bundle. */
    fun identity(profile: TunnelProfile): Identity? {
        val parsed = OpenVpnDocument.lines(profile.openVpnConfig)
        val inline = inlineBlocks(profile.openVpnConfig)
        val passphrase = profile.openVpnKeyPassphrase.takeIf { it.isNotEmpty() }?.toCharArray()
        fun file(key: String): ByteArray? = parsed.firstOrNull { it.key == key }?.arguments?.firstOrNull()?.let { Credentials.bytes(profile, it) }
            ?: inline[key]?.toByteArray()
        val pkcs12 = parsed.firstOrNull { it.key == "pkcs12" }?.arguments?.firstOrNull()?.let { Credentials.bytes(profile, it) }
            ?: inline["pkcs12"]?.let { Base64.getMimeDecoder().decode(it) }
        if (pkcs12 != null) {
            val bundle = KeyStore.getInstance("PKCS12").apply { load(ByteArrayInputStream(pkcs12), passphrase ?: CharArray(0)) }
            val alias = bundle.aliases().toList().firstOrNull { bundle.isKeyEntry(it) } ?: return null
            val key = bundle.getKey(alias, passphrase ?: CharArray(0)) as? PrivateKey ?: return null
            val chain = bundle.getCertificateChain(alias).orEmpty().map { it as X509Certificate }
            if (chain.isEmpty()) return null
            val authorities = bundle.aliases().toList().filter { bundle.isCertificateEntry(it) }.map { bundle.getCertificate(it) as X509Certificate }
            return Identity(PrivateKeyInfo.getInstance(key.encoded), chain, authorities + chain.drop(1))
        }
        val keyBytes = file("key") ?: return null
        val key = Credentials.privateKeyInfo(keyBytes, passphrase)
        val chain = Credentials.certificates(file("cert") ?: return null)
        if (chain.isEmpty() || !Credentials.keyMatches(key, chain.first())) return null
        return Identity(key, chain, emptyList())
    }

    /** The profile without private key material: key lines and inline key
     * blocks become a note; a PKCS#12 bundle becomes certificate files. Files
     * still used elsewhere (for example by stunnel) are kept. */
    fun withoutKeyMaterial(profile: TunnelProfile, identity: Identity): TunnelProfile {
        val parsed = OpenVpnDocument.lines(profile.openVpnConfig)
        val bundle = parsed.any { it.key == "pkcs12" } || "pkcs12" in inlineBlocks(profile.openVpnConfig)
        val hasAuthority = parsed.any { it.key == "ca" } || "ca" in inlineBlocks(profile.openVpnConfig)
        val removedFiles = parsed.filter { it.key == "key" || it.key == "pkcs12" }.mapNotNull { it.arguments.firstOrNull() }.map(Credentials::referenceName)
        val output = StringBuilder()
        var skipping: String? = null
        var passing: String? = null
        for (line in profile.openVpnConfig.lines()) {
            val text = line.trim()
            if (skipping != null) { if (text == "</$skipping>") skipping = null; continue }
            // Other inline blocks (certificates, tls-crypt keys) are copied as-is.
            if (passing != null) { if (text == "</$passing>") passing = null; output.append(line).append('\n'); continue }
            when {
                text == "<key>" || text == "<pkcs12>" -> { skipping = text.removeSurrounding("<", ">"); output.append(NOTE).append('\n') }
                Regex("<[a-z0-9-]+>").matches(text) -> { passing = text.removeSurrounding("<", ">"); output.append(line).append('\n') }
                OpenVpnDocument.tokenize(text).firstOrNull()?.removePrefix("--")?.lowercase() in setOf("key", "pkcs12") -> output.append(NOTE).append('\n')
                else -> output.append(line).append('\n')
            }
        }
        var files = profile.files
        if (bundle) {
            output.append("cert ").append(CERTIFICATE_FILE).append('\n')
            files = files + (CERTIFICATE_FILE to pem(identity.chain))
            if (!hasAuthority && identity.authorities.isNotEmpty()) {
                output.append("ca ").append(AUTHORITY_FILE).append('\n')
                files = files + (AUTHORITY_FILE to pem(identity.authorities))
            }
        }
        val stunnelUses = runCatching { StunnelDocument.parse(profile.config).credentialReferences().map(Credentials::referenceName) }.getOrDefault(emptyList())
        val openVpnUses = runCatching { OpenVpnDocument.credentialReferences(output.toString()).map(Credentials::referenceName) }.getOrDefault(emptyList())
        for (name in removedFiles) {
            if (name in stunnelUses) continue
            // A combined certificate-and-key file keeps only its certificates.
            files = if (name in openVpnUses) files + (name to pem(Credentials.certificates(Base64.getDecoder().decode(files.getValue(name)))))
                else files - name
        }
        return profile.copy(openVpnConfig = output.toString().trimEnd('\n') + "\n", files = files)
    }

    private fun pem(certificates: List<X509Certificate>): String {
        val text = StringWriter()
        PemWriter(text).use { writer -> certificates.forEach { writer.writeObject(PemObject("CERTIFICATE", it.encoded)) } }
        return Base64.getEncoder().encodeToString(text.toString().toByteArray())
    }

    private fun inlineBlocks(config: String): Map<String, String> {
        val blocks = mutableMapOf<String, StringBuilder>()
        var current: String? = null
        for (line in config.lines()) {
            val text = line.trim()
            when {
                current != null && text == "</$current>" -> current = null
                current != null -> blocks.getValue(current).append(line).append('\n')
                Regex("<([a-z0-9-]+)>").matches(text) -> { current = text.removeSurrounding("<", ">"); blocks[current] = StringBuilder() }
            }
        }
        return blocks.mapValues { it.value.toString() }
    }

    /** JCA algorithm for an OpenVPN PK_SIGN request, and whether the data is
     * the message (true) rather than a precomputed digest. Null when the
     * request cannot be served by Keystore. */
    fun signatureAlgorithm(request: String): String? {
        val parts = request.split(',')
        val parameters = parts.drop(1).mapNotNull { part -> part.split('=', limit = 2).takeIf { it.size == 2 }?.let { it[0] to it[1] } }.toMap()
        val message = parameters["data"] == "message"
        val digest = parameters["hashalg"]?.uppercase()?.replace("-", "")?.takeIf { it in setOf("SHA224", "SHA256", "SHA384", "SHA512") }
        return when (parts.first()) {
            "ECDSA" -> if (message) digest?.let { "${it}withECDSA" } else "NONEwithECDSA"
            "RSA_PKCS1_PADDING" -> if (message) digest?.let { "${it}withRSA" } else "NONEwithRSA"
            // Keystore uses a salt as long as the digest.
            "RSA_PKCS1_PSS_PADDING" -> if (message && parameters["saltlen"] == "digest") digest?.let { "${it}withRSA/PSS" } else null
            else -> null
        }
    }

    /** Signs for OpenVPN with the Keystore key; the key never leaves it. */
    fun sign(alias: String, data: ByteArray, request: String): ByteArray {
        val algorithm = signatureAlgorithm(request) ?: throw IllegalArgumentException("Unsupported signature request")
        val key = store().getKey(alias, null) as? PrivateKey ?: throw IllegalStateException("The OpenVPN client key is not on this phone")
        return Signature.getInstance(algorithm).run { initSign(key); update(data); sign() }
    }
}
