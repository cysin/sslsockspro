package io.github.cysin.sslsockspro.data

import io.github.cysin.sslsockspro.config.StunnelDocument
import io.github.cysin.sslsockspro.model.ConnectionMode
import io.github.cysin.sslsockspro.model.TunnelProfile
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.util.io.pem.PemObject
import org.bouncycastle.util.io.pem.PemWriter
import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.StringWriter
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.Date

class KeystoreKeysTest {
    private val pair: KeyPair = KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()
    private val authority: KeyPair = KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()
    private fun certificate(subject: String, key: KeyPair, signer: KeyPair): X509Certificate {
        val now = System.currentTimeMillis()
        val builder = JcaX509v3CertificateBuilder(X500Name("CN=Test CA"), BigInteger.valueOf(now), Date(now - 3600000), Date(now + 3600000),
            X500Name(subject), key.public)
        return JcaX509CertificateConverter().getCertificate(builder.build(JcaContentSignerBuilder("SHA256withECDSA").build(signer.private)))
    }
    private val ca = certificate("CN=Test CA", authority, authority)
    private val client = certificate("CN=Client", pair, authority)
    private fun pem(vararg objects: PemObject) = StringWriter().also { text -> PemWriter(text).use { w -> objects.forEach(w::writeObject) } }.toString()
    private val certificatePem = pem(PemObject("CERTIFICATE", client.encoded))
    private val keyPem = pem(PemObject("PRIVATE KEY", pair.private.encoded))
    private fun b64(text: String) = Base64.getEncoder().encodeToString(text.toByteArray())
    private fun profile(config: String, files: Map<String, String> = emptyMap(), stunnel: String = "") =
        TunnelProfile(name = "vpn", config = stunnel, mode = ConnectionMode.OPENVPN, openVpnConfig = config, files = files)

    @Test fun signatureRequestsMapToKeystoreAlgorithms() {
        assertEquals("SHA256withECDSA", KeystoreKeys.signatureAlgorithm("ECDSA,hashalg=SHA256,data=message"))
        assertEquals("NONEwithECDSA", KeystoreKeys.signatureAlgorithm("ECDSA"))
        assertEquals("SHA384withRSA", KeystoreKeys.signatureAlgorithm("RSA_PKCS1_PADDING,hashalg=SHA384,data=message"))
        assertEquals("NONEwithRSA", KeystoreKeys.signatureAlgorithm("RSA_PKCS1_PADDING"))
        assertEquals("SHA256withRSA/PSS", KeystoreKeys.signatureAlgorithm("RSA_PKCS1_PSS_PADDING,hashalg=SHA256,saltlen=digest,data=message"))
        assertNull(KeystoreKeys.signatureAlgorithm("RSA_PKCS1_PSS_PADDING,hashalg=SHA256,saltlen=max,data=message"))
        assertNull(KeystoreKeys.signatureAlgorithm("RSA_NO_PADDING"))
        assertNull(KeystoreKeys.signatureAlgorithm("ECDSA,hashalg=MD5,data=message"))
    }

    @Test fun separateFilesLoseTheKeyButKeepTheCertificate() {
        val vpn = profile("client\nremote 192.0.2.1 1194\nca ca.crt\ncert client.crt\nkey client.key\n",
            mapOf("ca.crt" to b64(pem(PemObject("CERTIFICATE", ca.encoded))), "client.crt" to b64(certificatePem), "client.key" to b64(keyPem)))
        val identity = KeystoreKeys.identity(vpn)!!
        val moved = KeystoreKeys.withoutKeyMaterial(vpn, identity)
        assertFalse(moved.files.containsKey("client.key"))
        assertTrue(moved.openVpnConfig.contains(KeystoreKeys.NOTE) && !moved.openVpnConfig.contains("key client.key"))
        assertTrue(moved.openVpnConfig.contains("cert client.crt"))
        OpenVpnDocument.validate(moved.openVpnConfig)
    }

    @Test fun inlineAndCombinedKeysAreRemovedWhileCertificatesStay() {
        val inline = profile("client\nremote 192.0.2.1 1194\n<ca>\n${pem(PemObject("CERTIFICATE", ca.encoded))}</ca>\n<cert>\n$certificatePem</cert>\n<key>\n$keyPem</key>\n")
        val moved = KeystoreKeys.withoutKeyMaterial(inline, KeystoreKeys.identity(inline)!!)
        assertFalse(moved.openVpnConfig.contains("PRIVATE KEY"))
        assertTrue(moved.openVpnConfig.contains("<cert>") && moved.openVpnConfig.contains("<ca>"))
        val combined = profile("client\nremote 192.0.2.1 1194\nca ca.crt\ncert client.pem\nkey client.pem\n",
            mapOf("ca.crt" to b64(pem(PemObject("CERTIFICATE", ca.encoded))), "client.pem" to b64(certificatePem + keyPem)))
        val stripped = KeystoreKeys.withoutKeyMaterial(combined, KeystoreKeys.identity(combined)!!)
        val remaining = String(Base64.getDecoder().decode(stripped.files.getValue("client.pem")))
        assertTrue(remaining.contains("CERTIFICATE") && !remaining.contains("PRIVATE KEY"))
    }

    @Test fun keysSharedWithStunnelStayForStunnel() {
        val vpn = profile("client\nremote 192.0.2.1 1194\nca ca.crt\ncert client.pem\nkey client.pem\n",
            mapOf("ca.crt" to b64(pem(PemObject("CERTIFICATE", ca.encoded))), "client.pem" to b64(certificatePem + keyPem)),
            stunnel = StunnelDocument.template("192.0.2.1"))
        val moved = KeystoreKeys.withoutKeyMaterial(vpn, KeystoreKeys.identity(vpn)!!)
        assertTrue(String(Base64.getDecoder().decode(moved.files.getValue("client.pem"))).contains("PRIVATE KEY"))
    }

    @Test fun pkcs12BundlesBecomeCertificateFiles() {
        val bundle = KeyStore.getInstance("PKCS12").apply {
            load(null, null)
            setKeyEntry("client", pair.private, "secret".toCharArray(), arrayOf(client))
            setCertificateEntry("ca", ca)
        }
        val bytes = ByteArrayOutputStream().also { bundle.store(it, "secret".toCharArray()) }.toByteArray()
        val vpn = profile("client\nremote 192.0.2.1 1194\npkcs12 client.p12\n", mapOf("client.p12" to Base64.getEncoder().encodeToString(bytes)))
            .copy(openVpnKeyPassphrase = "secret")
        val identity = KeystoreKeys.identity(vpn)!!
        val moved = KeystoreKeys.withoutKeyMaterial(vpn, identity)
        assertFalse(moved.files.containsKey("client.p12"))
        assertTrue(moved.openVpnConfig.contains("cert ${KeystoreKeys.CERTIFICATE_FILE}\n") && moved.openVpnConfig.contains("ca ${KeystoreKeys.AUTHORITY_FILE}\n"))
        // The bundle's chain starts with the client certificate.
        assertEquals(client, Credentials.certificates(Base64.getDecoder().decode(moved.files.getValue(KeystoreKeys.CERTIFICATE_FILE))).first())
        OpenVpnDocument.validate(moved.openVpnConfig)
    }

    @Test fun externalKeyRuntimesCarryNoKeyMaterial() {
        val config = "client\nremote 192.0.2.1 1194\nca ca.crt\ncert client.crt\nkey client.key\n<key>\nINLINE\n</key>\n"
        val text = OpenVpnDocument.runtime(config, { "/private/$it" }, "/private/control.sock", null, externalKey = true)
        assertTrue(text.contains("management-external-key pkcs1 pss digest\n"))
        assertFalse(text.contains("client.key") || text.contains("INLINE") || text.contains("<key>"))
    }
}
