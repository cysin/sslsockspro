package io.github.cysin.sslsockspro.data

import io.github.cysin.sslsockspro.config.StunnelDocument
import io.github.cysin.sslsockspro.model.ConnectionMode
import io.github.cysin.sslsockspro.model.ProxyKind
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory
import org.bouncycastle.util.io.pem.PemObject
import org.bouncycastle.util.io.pem.PemWriter
import org.junit.Assert.*
import org.junit.Test
import java.io.StringWriter
import java.security.SecureRandom
import java.util.Base64
import java.io.ByteArrayOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class PackageImporterTest {
    private fun zip(entries: Map<String, ByteArray>): ByteArray = ByteArrayOutputStream().also { output ->
        ZipOutputStream(output).use { zip -> entries.forEach { (name, bytes) -> zip.putNextEntry(ZipEntry(name)); zip.write(bytes); zip.closeEntry() } }
    }.toByteArray()

    @Test fun nestedDesktopClientPackageImportsWithoutFilesystemPaths() {
        val data = zip(mapOf("etc/stunnel/stunnel.conf" to StunnelDocument.template("192.0.2.1").toByteArray(),
            "etc/stunnel/client.pem" to "PRIVATE_CANARY".toByteArray(), "etc/stunnel/server-ca.crt" to "PUBLIC_CANARY".toByteArray()))
        val profiles = PackageImporter.profiles(PackageImporter.entries(data, "client.zip"))
        assertEquals(1, profiles.size)
        assertEquals(setOf("client.pem", "server-ca.crt"), profiles.first().files.keys)
    }
    @Test fun traversalAmbiguousNamesAndZipBombsAreRejected() {
        for (data in listOf(zip(mapOf("../client.pem" to byteArrayOf(1))),
            zip(mapOf("one/client.pem" to byteArrayOf(1), "two/client.pem" to byteArrayOf(2))),
            zip(mapOf("client.pem" to ByteArray(PackageImporter.MAX_FILE + 1))))) {
            assertThrows(IllegalArgumentException::class.java) { PackageImporter.entries(data, "client.zip") }
        }
    }
    @Test fun openVpnHooksAreRejectedAndInlineBlocksArePreserved() {
        val source = "client\nremote 192.0.2.1 1194\n<ca>\nPUBLIC_CERTIFICATE_CANARY\n</ca>\n"
        OpenVpnDocument.validate(source)
        assertTrue(OpenVpnDocument.runtime(source, { "/private/$it" }, "/private/control.sock", null).contains("<ca>\nPUBLIC_CERTIFICATE_CANARY\n</ca>"))
        assertThrows(IllegalArgumentException::class.java) { OpenVpnDocument.validate(source + "up /bin/sh\n") }
    }

    private val files = mapOf("client.conf" to StunnelDocument.template("192.0.2.1").toByteArray(),
        "client.pem" to "PRIVATE_CANARY".toByteArray(), "server-ca.crt" to "PUBLIC_CANARY".toByteArray())

    private fun signed(contents: Map<String, ByteArray>, manifestFiles: Map<String, ByteArray> = contents,
                       hints: String = ""): Pair<Map<String, ByteArray>, String> {
        val keys = Ed25519KeyPairGenerator().apply { init(Ed25519KeyGenerationParameters(SecureRandom())) }.generateKeyPair()
        val listing = manifestFiles.entries.joinToString(",") { "\"${it.key}\":\"${PackageManifest.sha256(it.value)}\"" }
        val manifest = "{\"format\":1,\"files\":{$listing}$hints}".toByteArray()
        val signature = Ed25519Signer().apply { init(true, keys.private as Ed25519PrivateKeyParameters); update(manifest, 0, manifest.size) }.generateSignature()
        val spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(keys.public as Ed25519PublicKeyParameters)
        val pem = StringWriter().also { PemWriter(it).use { writer -> writer.writeObject(PemObject("PUBLIC KEY", spki.encoded)) } }.toString()
        return contents + mapOf(PackageManifest.MANIFEST to manifest, PackageManifest.SIGNATURE to Base64.getEncoder().encode(signature),
            PackageManifest.OPERATOR_KEY to pem.toByteArray()) to PackageManifest.sha256(spki.encoded).uppercase()
    }

    @Test fun signedManifestsBindEveryFileAndCarryProfileSettings() {
        val (signedPackage, fingerprint) = signed(files, hints = ",\"profiles\":[{\"config\":\"client.conf\",\"name\":\"Office\",\"proxyKind\":\"SOCKS5\"}]")
        val plan = PackageImporter.plan(PackageImporter.entries(zip(signedPackage), "client.zip"))
        assertEquals(fingerprint, plan.operatorFingerprint)
        val profile = plan.profiles.single()
        assertEquals("Office", profile.name)
        assertEquals(ProxyKind.SOCKS5, profile.proxyKind)
        assertEquals(ConnectionMode.PROXY_VPN, profile.mode)
        assertEquals(fingerprint, profile.operatorKeyFingerprint)
        assertFalse(profile.files.keys.any { it in PackageManifest.NAMES })
    }

    @Test fun tamperedExtraMissingOrUnsignedManifestFilesAreRejected() {
        val (signedPackage, _) = signed(files)
        val cases = listOf(
            signedPackage + ("client.pem" to "SWAPPED".toByteArray()),
            signedPackage + ("extra.pem" to byteArrayOf(1)),
            signedPackage - "server-ca.crt",
            signedPackage - PackageManifest.SIGNATURE,
            signedPackage + (PackageManifest.SIGNATURE to Base64.getEncoder().encode(ByteArray(64))),
        )
        for (case in cases) assertThrows(IllegalArgumentException::class.java) { PackageImporter.plan(case) }
        assertNull(PackageImporter.plan(files).operatorFingerprint)
    }

    @Test fun checksumListsMustCoverTheWholePackage() {
        val sums = files.entries.filter { it.key != "client.pem" }.joinToString("") { PackageManifest.sha256(it.value) + "  " + it.key + "\n" }
        val error = assertThrows(IllegalArgumentException::class.java) {
            PackageImporter.entries(zip(files + ("SHA256SUMS" to sums.toByteArray())), "client.zip")
        }
        assertEquals("SHA256SUMS does not list client.pem", error.message)
        val complete = files.entries.joinToString("") { PackageManifest.sha256(it.value) + "  " + it.key + "\n" }
        assertEquals(files.keys, PackageImporter.entries(zip(files + ("SHA256SUMS" to complete.toByteArray())), "client.zip").keys)
    }

    /** Produced by tools/sign_package.py with a discarded throwaway key. */
    @Test fun packagesFromTheSigningToolVerify() {
        val bytes = javaClass.classLoader!!.getResourceAsStream("signed-package.zip")!!.use { it.readBytes() }
        val plan = PackageImporter.plan(PackageImporter.entries(bytes, "signed-package.zip"))
        assertEquals("2F14506A72BD2868086752940860B0F6193DDC1BA7095C792D2891C71AB86C78", plan.operatorFingerprint)
        assertEquals("Signed fixture", plan.profiles.single().name)
        assertEquals(ProxyKind.SOCKS5, plan.profiles.single().proxyKind)
    }
}
