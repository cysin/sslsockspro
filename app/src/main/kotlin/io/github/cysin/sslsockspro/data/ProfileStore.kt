package io.github.cysin.sslsockspro.data

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import io.github.cysin.sslsockspro.model.AppSettings
import io.github.cysin.sslsockspro.model.Backup
import io.github.cysin.sslsockspro.model.TunnelProfile
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.File
import java.io.RandomAccessFile
import java.security.KeyStore
import java.util.Base64
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** An authenticated atomic snapshot and a cross-process lock keep UI edits,
 * worker reads, and Keystore initialization consistent. */
class ProfileStore(context: Context) {
    private val file = AtomicFile(File(context.noBackupFilesDir, "profiles.enc"))
    private val lockFile = File(context.noBackupFilesDir, "profiles.lock")
    private val codec = Json { ignoreUnknownKeys = false; encodeDefaults = true }
    private val alias = "sslsockspro.profile-storage.v1"

    private fun <T> transaction(action: () -> T): T = synchronized(processLock) {
        RandomAccessFile(lockFile, "rw").channel.use { channel ->
            channel.lock().use { action() }
        }
    }

    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        return (store.getEntry(alias, null) as? KeyStore.SecretKeyEntry)?.secretKey ?: KeyGenerator.getInstance("AES", "AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).setRandomizedEncryptionRequired(true).build())
        }.generateKey()
    }

    fun read(): Backup = transaction { readUnlocked() }
    private fun readUnlocked(): Backup {
        if (!file.baseFile.exists() && !File(file.baseFile.path + ".bak").exists()) return Backup(profiles = emptyList())
        val data = file.openRead().use { PackageImporter.boundedRead(it, BackupCodec.MAX_BYTES + 28) }
        require(data.size >= 29) { "Stored profile snapshot is invalid" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, data.copyOfRange(0, 12)))
        cipher.updateAAD(alias.toByteArray())
        val clear = cipher.doFinal(data, 12, data.size - 12)
        try { return codec.decodeFromString<Backup>(clear.toString(Charsets.UTF_8)).also(::validate) }
        finally { clear.fill(0) }
    }

    fun write(backup: Backup) = transaction { writeUnlocked(backup) }
    private fun writeUnlocked(backup: Backup) {
        validate(backup)
        val clear = codec.encodeToString(backup).toByteArray()
        try {
            require(clear.size <= BackupCodec.MAX_BYTES) { "Profile storage exceeds 32 MiB" }
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key())
            cipher.updateAAD(alias.toByteArray())
            val stream = file.startWrite()
            try {
                stream.write(cipher.iv + cipher.doFinal(clear))
                file.finishWrite(stream)
            } catch (failure: Throwable) { file.failWrite(stream); throw failure }
        } finally { clear.fill(0) }
    }

    fun save(profile: TunnelProfile) = transaction {
        val backup = readUnlocked()
        val profiles = backup.profiles.filterNot { it.id == profile.id } + profile.copy(modifiedAt = System.currentTimeMillis())
        writeUnlocked(backup.copy(profiles = profiles, settings = backup.settings.copy(selectedProfileId = profile.id)))
    }

    fun delete(id: String) = transaction {
        val backup = readUnlocked()
        writeUnlocked(backup.copy(profiles = backup.profiles.filterNot { it.id == id },
            settings = backup.settings.copy(selectedProfileId = backup.settings.selectedProfileId?.takeUnless { it == id })))
    }

    fun settings(settings: AppSettings) = transaction { writeUnlocked(readUnlocked().copy(settings = settings)) }
    fun export(password: CharArray): ByteArray {
        val clear = codec.encodeToString(read()).toByteArray()
        try { return BackupCodec.encrypt(clear, password) } finally { clear.fill(0) }
    }
    fun restore(data: ByteArray, password: CharArray) {
        val clear = BackupCodec.decrypt(data, password)
        try {
            val imported = codec.decodeFromString<Backup>(clear.toString(Charsets.UTF_8)).also(::validate)
            transaction {
                val current = readUnlocked()
                writeUnlocked(current.copy(profiles = (current.profiles + imported.profiles).associateBy { it.id }.values.toList(),
                    settings = imported.settings))
            }
        } finally { clear.fill(0) }
    }

    private fun validate(backup: Backup) {
        require(backup.format == 1 && backup.profiles.size <= 128) { "Unsupported backup format or too many profiles" }
        require(backup.profiles.map { it.id }.toSet().size == backup.profiles.size) { "Duplicate profile IDs" }
        require(backup.settings.selectedProfileId == null || backup.profiles.any { it.id == backup.settings.selectedProfileId }) { "Selected profile is missing" }
        for (profile in backup.profiles) {
            require(runCatching { UUID.fromString(profile.id).toString().equals(profile.id, true) }.getOrDefault(false) &&
                profile.name.isNotBlank() && profile.name.length <= 128) { "Invalid profile identity" }
            require(profile.config.toByteArray().size <= 256 * 1024 && profile.openVpnConfig.toByteArray().size <= 256 * 1024) { "Configuration exceeds 256 KiB" }
            require(profile.files.size <= 128 && profile.files.keys.all { PackageImporter.safeName(it) }) { "Invalid credential filenames" }
            var total = 0L
            for (encoded in profile.files.values) {
                require(encoded.length <= (PackageImporter.MAX_FILE + 2) / 3 * 4) { "Credential exceeds 4 MiB" }
                val bytes = Base64.getDecoder().decode(encoded)
                total += bytes.size
                require(bytes.size <= PackageImporter.MAX_FILE && total <= PackageImporter.MAX_TOTAL) { "Profile credentials exceed their size limits" }
                bytes.fill(0)
            }
            require(profile.includedApps.size <= 256 && profile.includedApps.all { it.matches(Regex("[A-Za-z][A-Za-z0-9_.]*")) }) { "Invalid selected app package names" }
            require(listOf(profile.openVpnUsername, profile.openVpnPassword, profile.openVpnKeyPassphrase).all {
                it.length <= 4096 && it.none { c -> c == '\n' || c == '\r' || c == '\u0000' }
            }) { "Invalid OpenVPN credentials" }
        }
    }

    companion object { private val processLock = Any() }
}
