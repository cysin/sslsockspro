package io.github.cysin.sslsockspro.data

import io.github.cysin.sslsockspro.model.AppSettings
import io.github.cysin.sslsockspro.model.Backup
import io.github.cysin.sslsockspro.model.DnsMode
import io.github.cysin.sslsockspro.model.TunnelProfile
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class ProfileStoreTest {
    @get:Rule val folder = TemporaryFolder()

    /** Software stand-in for the Keystore with the same framing. */
    private class TestSealer : Sealer {
        private val key = SecretKeySpec(ByteArray(32) { it.toByte() }, "AES")
        override fun seal(clear: ByteArray, context: ByteArray): ByteArray {
            val nonce = ByteArray(12).also(java.security.SecureRandom()::nextBytes)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, nonce)); updateAAD(context) }
            return nonce + cipher.doFinal(clear)
        }
        override fun open(sealed: ByteArray, context: ByteArray): ByteArray {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
                init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, sealed.copyOfRange(0, 12))); updateAAD(context)
            }
            return cipher.doFinal(sealed, 12, sealed.size - 12)
        }
    }

    private val sealer = TestSealer()
    private fun store() = ProfileStore(folder.root, sealer)
    private fun profile(name: String) = TunnelProfile(name = name, config = "", openVpnPassword = "private-$name")

    @Test fun formatOneSnapshotsMigrateToSplitStorage() {
        val first = profile("first")
        val selected = profile("selected").copy(config = "client = yes\n[proxy]\naccept = 127.0.0.1:33008\n",
            includedApps = listOf("io.github.cysin.sslsockspro"), proxyUsername = "fixture-user", proxyPassword = "fixture-password")
        val profiles = listOf(first, selected)
        val encoder = kotlinx.serialization.json.Json { encodeDefaults = true }
        val encoded = profiles.joinToString(",") { encoder.encodeToString(TunnelProfile.serializer(), it) }
        val legacy = """{"format":1,"profiles":[$encoded],""" +
            """"settings":{"selectedProfileId":"${selected.id}","reconnect":false,"darkTheme":true}}"""
        File(folder.root, "profiles.enc").writeBytes(sealer.seal(legacy.toByteArray(), "sslsockspro.profile-storage.v1".toByteArray()))
        val settings = AppSettings(selectedProfileId = selected.id, reconnect = false, darkTheme = true)
        assertEquals(settings, store().settings())
        assertTrue(File(folder.root, "settings.enc").exists())
        val migrated = store().read()
        assertEquals(Backup.FORMAT, migrated.format)
        assertEquals(profiles, migrated.profiles)
        assertTrue(migrated.profiles.all { it.dnsMode == DnsMode.DOH })
        assertEquals(settings, migrated.settings)
        assertEquals(migrated, store().read())
    }

    @Test fun settingsChangesDoNotRewriteCredentialsAndDeletedSelectionsClear() {
        val store = store()
        val first = profile("first")
        store.save(first)
        val credentials = File(folder.root, "profiles.enc").readBytes()
        store.settings(store.settings().copy(darkTheme = false, reconnect = false))
        assertArrayEquals(credentials, File(folder.root, "profiles.enc").readBytes())
        assertThrows(IllegalArgumentException::class.java) { store.settings(AppSettings(selectedProfileId = profile("missing").id)) }
        store.delete(first.id)
        assertNull(store.read().settings.selectedProfileId)
        assertEquals(false, store.read().settings.reconnect)
    }

    @Test fun tamperingNewerFormatsAndLegacyAtomicBackupsAreHandled() {
        val store = store()
        store.save(profile("kept"))
        val file = File(folder.root, "profiles.enc")
        val original = file.readBytes()
        file.writeBytes(original.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() })
        assertThrows(Exception::class.java) { store.read() }
        // An interrupted legacy AtomicFile write left the previous snapshot in .bak.
        File(folder.root, "profiles.enc.bak").writeBytes(original)
        assertEquals("kept", store.read().profiles.single().name)
        assertFalse(File(folder.root, "profiles.enc.bak").exists())
        val newer = """{"format":3,"profiles":[],"settings":{},"futureField":1}"""
        assertThrows(IllegalArgumentException::class.java) { ProfileStore.decodeBackup(newer) }
        val older = """{"format":1,"profiles":[],"settings":{"reconnect":false},"futureField":1}"""
        assertEquals(Backup(profiles = emptyList(), settings = AppSettings(reconnect = false)), ProfileStore.decodeBackup(older))
    }

    @Test fun portableBackupsRestoreProfilesAndSettings() {
        val store = store()
        val first = profile("first")
        store.save(first)
        val password = "a long backup password".toCharArray()
        val backup = store.export(password)
        store.delete(first.id)
        store.restore(backup, password)
        assertEquals(first.id, store.read().settings.selectedProfileId)
        assertEquals("private-first", store.profile(first.id)!!.openVpnPassword)
    }
}
