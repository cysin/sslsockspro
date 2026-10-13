package io.github.cysin.sslsockspro.data

import io.github.cysin.sslsockspro.config.StunnelDocument
import io.github.cysin.sslsockspro.model.ConnectionMode
import io.github.cysin.sslsockspro.model.TunnelProfile
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.PEMEncryptedKeyPair
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo
import org.bouncycastle.util.io.pem.PemObject
import java.io.ByteArrayInputStream
import java.io.File
import java.io.StringReader
import java.io.StringWriter
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.Date

data class CertificateSummary(val name: String, val subject: String, val expires: Long, val fingerprint: String, val clientIdentity: Boolean)

object Credentials {
    private val provider = BouncyCastleProvider()
    fun referenceName(reference: String): String = reference.removeSurrounding("\"").substringAfterLast('/').substringAfterLast('\\')
    fun bytes(profile: TunnelProfile, reference: String): ByteArray = Base64.getDecoder().decode(profile.files[referenceName(reference)]
        ?: throw IllegalArgumentException("Import the referenced credential file: ${referenceName(reference)}"))

    fun certificates(bytes: ByteArray): List<X509Certificate> {
        val factory = CertificateFactory.getInstance("X.509")
        val text = bytes.toString(Charsets.UTF_8)
        if (!text.contains("-----BEGIN ")) return factory
            .generateCertificates(ByteArrayInputStream(bytes)).map { it as X509Certificate }
        // Combined client PEM files also contain private keys. Certificate
        // factories differ in how they handle those blocks, so select only
        // certificates before passing their DER encoding to the platform.
        return PEMParser(StringReader(text)).use { parser ->
            buildList {
                while (true) {
                    val item = parser.readObject() ?: break
                    if (item is X509CertificateHolder) add(factory.generateCertificate(
                        ByteArrayInputStream(item.encoded)) as X509Certificate)
                }
            }
        }
    }

    fun privateKey(bytes: ByteArray, password: CharArray? = null): PrivateKey {
        val converter = JcaPEMKeyConverter().setProvider(provider)
        PEMParser(StringReader(bytes.toString(Charsets.UTF_8))).use { parser ->
            while (true) {
                when (val item = parser.readObject() ?: break) {
                    is PrivateKeyInfo -> return converter.getPrivateKey(item)
                    is PEMKeyPair -> return converter.getPrivateKey(item.privateKeyInfo)
                    is PEMEncryptedKeyPair -> {
                        require(password != null) { "This private key needs a passphrase" }
                        return converter.getPrivateKey(item.decryptKeyPair(JcePEMDecryptorProviderBuilder().setProvider(provider).build(password)).privateKeyInfo)
                    }
                    is PKCS8EncryptedPrivateKeyInfo -> {
                        require(password != null) { "This private key needs a passphrase" }
                        return converter.getPrivateKey(item.decryptPrivateKeyInfo(JceOpenSSLPKCS8DecryptorProviderBuilder().setProvider(provider).build(password)))
                    }
                }
            }
        }
        throw IllegalArgumentException("No supported private key was found")
    }

    fun normalizeIdentity(bytes: ByteArray, password: CharArray): ByteArray {
        val key = privateKey(bytes, password)
        val output = StringWriter()
        JcaPEMWriter(output).use { writer ->
            runCatching { certificates(bytes) }.getOrDefault(emptyList()).forEach(writer::writeObject)
            // PKCS#8 retains EC curve parameters even when the platform key
            // omits them from its nested SEC1 representation.
            writer.writeObject(PemObject("PRIVATE KEY", key.encoded))
        }
        return output.toString().toByteArray()
    }

    fun validate(profile: TunnelProfile) {
        if (profile.mode == ConnectionMode.OPENVPN) {
            OpenVpnDocument.validate(profile.openVpnConfig)
            if (!profile.openVpnViaStunnel) return
        }
        val document = StunnelDocument.parse(profile.config)
        document.validate()
        for (section in document.sections) {
            val authority = certificates(bytes(profile, document.effective(section, "cafile")!!))
            require(authority.isNotEmpty() && authority.all { it.basicConstraints >= 0 }) { "CAfile must contain trusted CA certificates" }
            authority.forEach { it.checkValidity() }
            val chain = certificates(bytes(profile, document.effective(section, "cert")!!))
            require(chain.isNotEmpty()) { "Client certificate is missing" }
            val client = chain.first()
            client.checkValidity()
            require(client.basicConstraints < 0) { "A CA certificate cannot be used as the client identity" }
            require(client.extendedKeyUsage == null || "1.3.6.1.5.5.7.3.2" in client.extendedKeyUsage) { "Certificate does not permit client authentication" }
            val key = privateKey(bytes(profile, document.effective(section, "key")!!))
            val algorithm = when (key.algorithm.uppercase()) {
                "RSA" -> "SHA256withRSA"
                "EC", "ECDSA" -> "SHA256withECDSA"
                "ED25519", "EDDSA" -> "Ed25519"
                else -> throw IllegalArgumentException("Unsupported client key algorithm")
            }
            val challenge = "SSLSocksPro local key validation".toByteArray()
            val signed = Signature.getInstance(algorithm, provider).run { initSign(key); update(challenge); sign() }
            require(Signature.getInstance(algorithm, provider).run { initVerify(client.publicKey); update(challenge); verify(signed) }) { "Client certificate and private key do not match" }
            for (index in 0 until chain.lastIndex) {
                chain[index + 1].checkValidity()
                chain[index].verify(chain[index + 1].publicKey)
            }
        }
    }

    fun summaries(profile: TunnelProfile): List<CertificateSummary> = profile.files.flatMap { (name, encoded) ->
        runCatching {
            certificates(Base64.getDecoder().decode(encoded)).map { certificate ->
                CertificateSummary(name, certificate.subjectX500Principal.name, certificate.notAfter.time,
                    java.security.MessageDigest.getInstance("SHA-256").digest(certificate.encoded).joinToString(":") { "%02X".format(it) }, certificate.basicConstraints < 0)
            }
        }.getOrDefault(emptyList())
    }

    fun materialize(profile: TunnelProfile, directory: File): (String) -> String {
        require(directory.isDirectory && !java.nio.file.Files.isSymbolicLink(directory.toPath())) { "Invalid runtime credential directory" }
        directory.setReadable(false, false); directory.setWritable(false, false); directory.setExecutable(false, false)
        directory.setReadable(true, true); directory.setWritable(true, true); directory.setExecutable(true, true)
        return { reference ->
            val name = referenceName(reference)
            require(PackageImporter.safeName(name)) { "Invalid credential reference" }
            val diskName = java.security.MessageDigest.getInstance("SHA-256").digest(name.toByteArray()).joinToString("") { "%02x".format(it) } + ".pem"
            val target = File(directory, diskName)
            require(!java.nio.file.Files.isSymbolicLink(target.toPath())) { "Credential links are unsupported" }
            target.writeBytes(bytes(profile, reference))
            target.setReadable(false, false); target.setWritable(false, false)
            target.setReadable(true, true); target.setWritable(true, true)
            target.absolutePath
        }
    }
}
