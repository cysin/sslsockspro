package io.github.cysin.sslsockspro.data

import io.github.cysin.sslsockspro.config.StunnelDocument
import io.github.cysin.sslsockspro.model.TunnelProfile
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.PKCS8Generator
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder
import org.bouncycastle.util.io.pem.PemWriter
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.util.io.pem.PemObject
import org.junit.Assert.*
import org.junit.Test
import java.io.StringWriter
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.Date

class CredentialsTest {
    private val provider = BouncyCastleProvider()
    private fun key(): KeyPair = KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()
    private fun certificate(pair: KeyPair, signer: KeyPair, ca: Boolean, expired: Boolean = false, serverOnly: Boolean = false): X509Certificate {
        val now = System.currentTimeMillis()
        val builder = JcaX509v3CertificateBuilder(X500Name("CN=Fixture CA"), BigInteger.valueOf(if (ca) 1 else 2),
            Date(now - 3600000), Date(if (expired) now - 1000 else now + 3600000),
            X500Name(if (ca) "CN=Fixture CA" else "CN=Fixture Client"), pair.public)
        builder.addExtension(Extension.basicConstraints, true, BasicConstraints(ca))
        if (!ca) builder.addExtension(Extension.extendedKeyUsage, false, ExtendedKeyUsage(if (serverOnly) KeyPurposeId.id_kp_serverAuth else KeyPurposeId.id_kp_clientAuth))
        return JcaX509CertificateConverter().setProvider(provider).getCertificate(
            builder.build(JcaContentSignerBuilder("SHA256withECDSA").setProvider(provider).build(signer.private)))
    }
    private fun pem(vararg objects: Any): String {
        val text = StringWriter()
        JcaPEMWriter(text).use { writer -> objects.forEach { value ->
            writer.writeObject(if (value is PrivateKey) PemObject("PRIVATE KEY", value.encoded) else value)
        } }
        return Base64.getEncoder().encodeToString(text.toString().toByteArray())
    }
    private fun profile(expired: Boolean = false, mismatch: Boolean = false, serverOnly: Boolean = false, caAsIdentity: Boolean = false,
                        client: KeyPair = key(), other: () -> KeyPair = ::key): TunnelProfile {
        val authority = key()
        val ca = certificate(authority, authority, true)
        val leaf = certificate(client, authority, false, expired, serverOnly)
        return TunnelProfile(name = "fixture", config = StunnelDocument.template("192.0.2.1"), files = mapOf(
            "server-ca.crt" to pem(ca), "client.pem" to pem(if (caAsIdentity) ca else leaf, ca,
                if (mismatch) other().private else if (caAsIdentity) authority.private else client.private)))
    }
    private fun encrypted(key: PrivateKey, password: String, pkcs8: Boolean): ByteArray {
        val text = StringWriter()
        PemWriter(text).use { writer ->
            writer.writeObject(if (pkcs8) JcaPKCS8Generator(key, JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.AES_256_CBC)
                .setProvider(provider).setPRF(PKCS8Generator.PRF_HMACSHA256).setIterationCount(2048)
                .setPassword(password.toCharArray()).build()).generate()
                else JcaMiscPEMGenerator(key, JcePEMEncryptorBuilder("AES-256-CBC").setProvider(provider).build(password.toCharArray())).generate())
        }
        return text.toString().toByteArray()
    }
    @Test fun matchingClientIdentityAndCaAreAccepted() {
        val profile = profile()
        Credentials.validate(profile)
        val normalized = Credentials.normalizeIdentity(Credentials.bytes(profile, "client.pem"), charArrayOf())
        Credentials.validate(profile.copy(files = profile.files +
            ("client.pem" to Base64.getEncoder().encodeToString(normalized))))
    }
    @Test fun expiredCertificateAndMismatchedPrivateKeyAreRejected() {
        assertThrows(java.security.cert.CertificateExpiredException::class.java) { Credentials.validate(profile(expired = true)) }
        assertThrows(IllegalArgumentException::class.java) { Credentials.validate(profile(mismatch = true)) }
    }
    @Test fun ServerRoleOrCaCannotBeUsedAsClientIdentity() {
        assertThrows(IllegalArgumentException::class.java) { Credentials.validate(profile(serverOnly = true)) }
        assertThrows(IllegalArgumentException::class.java) { Credentials.validate(profile(caAsIdentity = true)) }
    }
    @Test fun rsaAndEd25519IdentitiesAreMatchedWithoutPlatformProviders() {
        for (algorithm in listOf("RSA", "Ed25519")) {
            val generate = { KeyPairGenerator.getInstance(algorithm).generateKeyPair() }
            Credentials.validate(profile(client = generate()))
            assertThrows(IllegalArgumentException::class.java) { Credentials.validate(profile(client = generate(), mismatch = true, other = generate)) }
        }
    }
    @Test fun encryptedPemAndPkcs8KeysUnlockOnlyWithTheirPassphrase() {
        for (pkcs8 in listOf(false, true)) {
            val pair = key()
            val locked = encrypted(pair.private, "correct horse battery", pkcs8)
            assertThrows(IllegalArgumentException::class.java) { Credentials.privateKeyInfo(locked) }
            assertThrows(IllegalArgumentException::class.java) { Credentials.normalizeIdentity(locked, "wrong passphrase".toCharArray()) }
            val unlocked = Credentials.privateKeyInfo(Credentials.normalizeIdentity(locked, "correct horse battery".toCharArray()))
            // SEC1 and PKCS#8 encodings differ in optional fields; the scalar must not.
            assertEquals((pair.private as java.security.interfaces.ECPrivateKey).s,
                org.bouncycastle.asn1.sec.ECPrivateKey.getInstance(unlocked.parsePrivateKey()).key)
        }
    }
}
