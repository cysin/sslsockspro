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
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
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
    private fun profile(expired: Boolean = false, mismatch: Boolean = false, serverOnly: Boolean = false, caAsIdentity: Boolean = false): TunnelProfile {
        val authority = key()
        val client = key()
        val ca = certificate(authority, authority, true)
        val leaf = certificate(client, authority, false, expired, serverOnly)
        return TunnelProfile(name = "fixture", config = StunnelDocument.template("192.0.2.1"), files = mapOf(
            "server-ca.crt" to pem(ca), "client.pem" to pem(if (caAsIdentity) ca else leaf, ca,
                if (mismatch) key().private else if (caAsIdentity) authority.private else client.private)))
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
}
