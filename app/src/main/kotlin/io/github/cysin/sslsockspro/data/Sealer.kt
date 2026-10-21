package io.github.cysin.sslsockspro.data

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.io.FileOutputStream
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Authenticated encryption for stored snapshots. [context] is bound as
 * associated data so one snapshot cannot be substituted for another. */
interface Sealer {
    fun seal(clear: ByteArray, context: ByteArray): ByteArray
    fun open(sealed: ByteArray, context: ByteArray): ByteArray
}

/** AES-256-GCM with a non-exportable Android Keystore key. The key never
 * leaves the Keystore; every operation is performed by it. */
class KeystoreSealer(private val alias: String = "sslsockspro.profile-storage.v1") : Sealer {
    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        return (store.getEntry(alias, null) as? KeyStore.SecretKeyEntry)?.secretKey ?: KeyGenerator.getInstance("AES", "AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).setRandomizedEncryptionRequired(true).build())
        }.generateKey()
    }

    override fun seal(clear: ByteArray, context: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key())
        cipher.updateAAD(context)
        return cipher.iv + cipher.doFinal(clear)
    }

    override fun open(sealed: ByteArray, context: ByteArray): ByteArray {
        require(sealed.size >= 29) { "Stored snapshot is invalid" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, sealed.copyOfRange(0, 12)))
        cipher.updateAAD(context)
        return cipher.doFinal(sealed, 12, sealed.size - 12)
    }
}

/** Crash-safe replacement of one file. Callers hold the store lock. Older
 * android.util.AtomicFile versions left a ".bak" copy while writing; it is
 * the complete previous snapshot and takes precedence, as it did there. */
internal class SnapshotFile(val base: File) {
    private val legacyBackup = File(base.path + ".bak")
    private val pending = File(base.path + ".new")

    fun exists(): Boolean = base.exists() || legacyBackup.exists()

    fun read(limit: Int): ByteArray? {
        if (legacyBackup.exists()) check(legacyBackup.renameTo(base)) { "Could not recover the previous snapshot" }
        pending.delete()
        if (!base.exists()) return null
        return base.inputStream().use { PackageImporter.boundedRead(it, limit) }
    }

    fun write(data: ByteArray) {
        try {
            FileOutputStream(pending).use { stream -> stream.write(data); stream.fd.sync() }
            check(pending.renameTo(base)) { "Could not replace the stored snapshot" }
            legacyBackup.delete()
        } finally { pending.delete() }
    }
}
