package io.github.cysin.sslsockspro.data

import io.github.cysin.sslsockspro.config.StunnelDocument
import org.junit.Assert.*
import org.junit.Test
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
}
