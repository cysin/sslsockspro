package io.github.cysin.sslsockspro

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.cysin.sslsockspro.data.ProfileStore
import io.github.cysin.sslsockspro.model.TunnelProfile
import io.github.cysin.sslsockspro.model.ConnectionMode
import io.github.cysin.sslsockspro.model.ProxyKind
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

@RunWith(AndroidJUnit4::class)
class ProfileStorageTest {
    @Test fun keystoreEncryptionAtomicEditsAndAuthenticatedBackup() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val store = (context.applicationContext as TunnelApplication).profiles
        val old = store.read()
        val password = "temporary-test-password".toCharArray()
        try {
            val profiles = (1..8).map { TunnelProfile(name = "storage-test-$it", config = "",
                mode = ConnectionMode.entries[it % 3], proxyKind = ProxyKind.entries[it % 2],
                openVpnViaStunnel = it % 2 == 0, suppressServiceBindings = it % 2 == 1,
                proxyIpv6 = it % 2 == 0,
                includedApps = listOf(context.packageName), openVpnPassword = "unambiguous-private-test-value") }
            val pool = Executors.newFixedThreadPool(4)
            try {
                val futures = profiles.map { profile -> pool.submit { ProfileStore(context).save(profile) } }
                futures.forEach { it.get(20, TimeUnit.SECONDS) }
            } finally { pool.shutdownNow() }
            assertTrue(store.read().profiles.map { it.id }.containsAll(profiles.map { it.id }))
            profiles.forEach { expected ->
                val actual = store.read().profiles.single { it.id == expected.id }
                assertEquals(expected, actual.copy(modifiedAt = expected.modifiedAt))
            }
            val encrypted = File(context.noBackupFilesDir, "profiles.enc").readBytes()
            assertFalse(encrypted.toString(Charsets.ISO_8859_1).contains("unambiguous-private-test-value"))
            val backup = store.export(password)
            store.delete(profiles.first().id)
            store.restore(backup, password)
            assertTrue(store.read().profiles.any { it.id == profiles.first().id })
            val previous = store.read()
            backup[backup.lastIndex] = (backup.last().toInt() xor 1).toByte()
            assertThrows(Exception::class.java) { store.restore(backup, password) }
            assertEquals(previous, store.read())
            val file = File(context.noBackupFilesDir, "profiles.enc")
            val damaged = encrypted.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
            file.writeBytes(damaged)
            try { assertThrows(Exception::class.java) { store.read() } }
            finally { file.writeBytes(encrypted) }
        } finally { password.fill('\u0000'); store.write(old) }
    }
}
