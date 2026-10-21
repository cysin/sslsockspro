package io.github.cysin.sslsockspro.data

import io.github.cysin.sslsockspro.config.StunnelDocument
import io.github.cysin.sslsockspro.model.ConnectionMode
import io.github.cysin.sslsockspro.model.TunnelProfile
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.pkcs.PBES2Parameters
import org.bouncycastle.asn1.pkcs.PBKDF2Params
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.crypto.PBEParametersGenerator
import org.bouncycastle.crypto.digests.SHA1Digest
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.digests.SHA384Digest
import org.bouncycastle.crypto.digests.SHA512Digest
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.engines.DESedeEngine
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator
import org.bouncycastle.crypto.modes.CBCBlockCipher
import org.bouncycastle.crypto.paddings.PKCS7Padding
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import org.bouncycastle.crypto.params.RSAKeyParameters
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters
import org.bouncycastle.crypto.util.PrivateKeyFactory
import org.bouncycastle.crypto.util.PublicKeyFactory
import org.bouncycastle.math.ec.FixedPointCombMultiplier
import org.bouncycastle.openssl.PEMEncryptedKeyPair
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.bc.BcPEMDecryptorProvider
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo
import org.bouncycastle.util.io.pem.PemObject
import org.bouncycastle.util.io.pem.PemWriter
import java.io.ByteArrayInputStream
import java.io.File
import java.io.StringReader
import java.io.StringWriter
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64

data class CertificateSummary(val name: String, val subject: String, val expires: Long, val fingerprint: String, val clientIdentity: Boolean)

object Credentials {
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

    /** Parses and, when needed, decrypts a PEM private key with Bouncy Castle's
     * lightweight API. No reflective JCA provider is involved, so behavior is
     * identical on the JVM and Android and R8 can remove unused algorithms. */
    fun privateKeyInfo(bytes: ByteArray, password: CharArray? = null): PrivateKeyInfo {
        PEMParser(StringReader(bytes.toString(Charsets.UTF_8))).use { parser ->
            while (true) {
                when (val item = parser.readObject() ?: break) {
                    is PrivateKeyInfo -> return item
                    is PEMKeyPair -> return item.privateKeyInfo
                    is PEMEncryptedKeyPair -> {
                        require(password != null) { "This private key needs a passphrase" }
                        return runCatching { item.decryptKeyPair(BcPEMDecryptorProvider(password)).privateKeyInfo }
                            .getOrElse { throw IllegalArgumentException("Wrong passphrase or damaged private key") }
                    }
                    is PKCS8EncryptedPrivateKeyInfo -> {
                        require(password != null) { "This private key needs a passphrase" }
                        return decryptPkcs8(item, password)
                    }
                }
            }
        }
        throw IllegalArgumentException("No supported private key was found")
    }

    private fun decryptPkcs8(item: PKCS8EncryptedPrivateKeyInfo, password: CharArray): PrivateKeyInfo {
        val algorithm = item.encryptionAlgorithm
        require(algorithm.algorithm == PKCSObjectIdentifiers.id_PBES2) { "Only PBES2-encrypted PKCS#8 keys are supported" }
        val parameters = PBES2Parameters.getInstance(algorithm.parameters)
        require(parameters.keyDerivationFunc.algorithm == PKCSObjectIdentifiers.id_PBKDF2) { "Unsupported PKCS#8 key derivation" }
        val derivation = PBKDF2Params.getInstance(parameters.keyDerivationFunc.parameters)
        val digest = when (derivation.prf.algorithm) {
            PKCSObjectIdentifiers.id_hmacWithSHA1 -> SHA1Digest()
            PKCSObjectIdentifiers.id_hmacWithSHA256 -> SHA256Digest()
            PKCSObjectIdentifiers.id_hmacWithSHA384 -> SHA384Digest()
            PKCSObjectIdentifiers.id_hmacWithSHA512 -> SHA512Digest()
            else -> throw IllegalArgumentException("Unsupported PKCS#8 key derivation")
        }
        val scheme = parameters.encryptionScheme
        val (engine, keySize) = when (scheme.algorithm) {
            NISTObjectIdentifiers.id_aes128_CBC -> AESEngine.newInstance() to 16
            NISTObjectIdentifiers.id_aes192_CBC -> AESEngine.newInstance() to 24
            NISTObjectIdentifiers.id_aes256_CBC -> AESEngine.newInstance() to 32
            PKCSObjectIdentifiers.des_EDE3_CBC -> DESedeEngine() to 24
            else -> throw IllegalArgumentException("Unsupported PKCS#8 key encryption")
        }
        val iterations = derivation.iterationCount.toInt()
        // Bound the CPU an imported key can demand from the phone.
        require(iterations in 1..10_000_000) { "Unsupported PKCS#8 iteration count" }
        require(derivation.keyLength == null || derivation.keyLength.toInt() == keySize) { "Inconsistent PKCS#8 key length" }
        val secret = PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(password)
        try {
            val generator = PKCS5S2ParametersGenerator(digest).apply { init(secret, derivation.salt, iterations) }
            val key = generator.generateDerivedParameters(keySize * 8) as KeyParameter
            val cipher = PaddedBufferedBlockCipher(CBCBlockCipher.newInstance(engine), PKCS7Padding())
            cipher.init(false, ParametersWithIV(key, ASN1OctetString.getInstance(scheme.parameters).octets))
            val encrypted = item.encryptedData
            val clear = ByteArray(cipher.getOutputSize(encrypted.size))
            try {
                val length = cipher.processBytes(encrypted, 0, encrypted.size, clear, 0).let { it + cipher.doFinal(clear, it) }
                return PrivateKeyInfo.getInstance(clear.copyOf(length))
            } catch (failure: Exception) {
                throw IllegalArgumentException("Wrong passphrase or damaged private key")
            } finally { clear.fill(0) }
        } finally { secret.fill(0) }
    }

    /** Derives the public key from the private key and compares it with the
     * certificate, without relying on platform signature providers. */
    private fun requireMatchingKey(key: PrivateKeyInfo, certificate: X509Certificate) =
        require(keyMatches(key, certificate)) { "Client certificate and private key do not match" }

    fun keyMatches(key: PrivateKeyInfo, certificate: X509Certificate): Boolean {
        val private = runCatching { PrivateKeyFactory.createKey(key) }
            .getOrElse { throw IllegalArgumentException("Unsupported client key algorithm") }
        val public = runCatching { PublicKeyFactory.createKey(SubjectPublicKeyInfo.getInstance(certificate.publicKey.encoded)) }
            .getOrElse { throw IllegalArgumentException("Unsupported client certificate key algorithm") }
        val matches = when (private) {
            is RSAPrivateCrtKeyParameters -> public is RSAKeyParameters && !public.isPrivate &&
                public.modulus == private.modulus && public.exponent == private.publicExponent
            is ECPrivateKeyParameters -> public is ECPublicKeyParameters && public.parameters.curve == private.parameters.curve &&
                FixedPointCombMultiplier().multiply(private.parameters.g, private.d).normalize().getEncoded(false)
                    .contentEquals(public.q.normalize().getEncoded(false))
            is Ed25519PrivateKeyParameters -> public is Ed25519PublicKeyParameters &&
                private.generatePublicKey().encoded.contentEquals(public.encoded)
            else -> throw IllegalArgumentException("Unsupported client key algorithm")
        }
        return matches
    }

    fun normalizeIdentity(bytes: ByteArray, password: CharArray): ByteArray {
        val key = privateKeyInfo(bytes, password)
        val output = StringWriter()
        PemWriter(output).use { writer ->
            runCatching { certificates(bytes) }.getOrDefault(emptyList()).forEach { writer.writeObject(PemObject("CERTIFICATE", it.encoded)) }
            // PKCS#8 retains EC curve parameters even when a nested SEC1
            // representation omits them.
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
            requireMatchingKey(privateKeyInfo(bytes(profile, document.effective(section, "key")!!)), client)
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
