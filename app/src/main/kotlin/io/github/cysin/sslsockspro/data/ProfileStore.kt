package io.github.cysin.sslsockspro.data

import android.content.Context
import io.github.cysin.sslsockspro.model.AppSettings
import io.github.cysin.sslsockspro.model.Backup
import io.github.cysin.sslsockspro.model.TunnelProfile
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.File
import java.io.RandomAccessFile
import java.util.Base64
import java.util.UUID

/** Authenticated atomic snapshots and a cross-process lock keep UI edits,
 * worker reads, and Keystore initialization consistent. Profiles and their
 * credentials live in one snapshot; settings live in a small separate one so
 * toggling a setting never decrypts or rewrites credentials. */
class ProfileStore(directory: File, private val sealer: Sealer) {
    constructor(context: Context) : this(context.noBackupFilesDir, KeystoreSealer())

    private val profileFile = SnapshotFile(File(directory, "profiles.enc"))
    private val settingsFile = SnapshotFile(File(directory, "settings.enc"))
    private val lockFile = File(directory, "profiles.lock")

    /** Format 1 stored settings inside the profile snapshot. */
    @Serializable
    private data class StoredProfiles(val format: Int, val profiles: List<TunnelProfile>, val settings: AppSettings? = null)

    @Serializable
    private data class StoredSettings(val format: Int, val settings: AppSettings)

    private fun <T> transaction(action: () -> T): T = synchronized(processLock) {
        RandomAccessFile(lockFile, "rw").channel.use { channel ->
            channel.lock().use { action() }
        }
    }

    private fun open(file: SnapshotFile, context: ByteArray, limit: Int): String? {
        val data = file.read(limit) ?: return null
        val clear = sealer.open(data, context)
        try { return clear.toString(Charsets.UTF_8) } finally { clear.fill(0) }
    }

    private fun seal(file: SnapshotFile, context: ByteArray, text: String) {
        val clear = text.toByteArray()
        try {
            require(clear.size <= BackupCodec.MAX_BYTES) { "Profile storage exceeds 32 MiB" }
            file.write(sealer.seal(clear, context))
        } finally { clear.fill(0) }
    }

    private fun readProfilesUnlocked(): List<TunnelProfile> {
        val stored = open(profileFile, PROFILE_CONTEXT, BackupCodec.MAX_BYTES + 28)?.let { codec.decodeFromString<StoredProfiles>(it) }
            ?: return emptyList()
        requireSupported(stored.format)
        validateProfiles(stored.profiles)
        if (stored.format < Backup.FORMAT) {
            // Split format-1 storage: settings first, so an interruption
            // leaves the original snapshot to migrate again.
            writeSettingsUnlocked(stored.settings ?: AppSettings())
            writeProfilesUnlocked(stored.profiles)
        }
        return stored.profiles
    }

    private fun storedSettingsUnlocked(): AppSettings {
        // Format-1 settings are inside the profile snapshot; reading it migrates them.
        if (!settingsFile.exists() && profileFile.exists()) readProfilesUnlocked()
        return open(settingsFile, SETTINGS_CONTEXT, 64 * 1024)?.let { codec.decodeFromString<StoredSettings>(it) }
            ?.also { requireSupported(it.format) }?.settings ?: AppSettings()
    }

    private fun readSettingsUnlocked(profiles: List<TunnelProfile>): AppSettings {
        val settings = storedSettingsUnlocked()
        // Another process may have deleted the selected profile.
        return if (settings.selectedProfileId == null || profiles.any { it.id == settings.selectedProfileId }) settings
            else settings.copy(selectedProfileId = null)
    }

    private fun writeProfilesUnlocked(profiles: List<TunnelProfile>) {
        validateProfiles(profiles)
        seal(profileFile, PROFILE_CONTEXT, codec.encodeToString(StoredProfiles(Backup.FORMAT, profiles)))
    }

    private fun writeSettingsUnlocked(settings: AppSettings) {
        seal(settingsFile, SETTINGS_CONTEXT, codec.encodeToString(StoredSettings(Backup.FORMAT, settings)))
    }

    fun read(): Backup = transaction {
        val profiles = readProfilesUnlocked()
        Backup(profiles = profiles, settings = readSettingsUnlocked(profiles))
    }

    /** Settings only; credentials are not decrypted after migration. The
     * selected profile may since have been deleted by another process. */
    fun settings(): AppSettings = transaction { storedSettingsUnlocked() }

    fun profile(id: String): TunnelProfile? = transaction { readProfilesUnlocked().firstOrNull { it.id == id } }

    fun write(backup: Backup) = transaction {
        validate(backup)
        writeProfilesUnlocked(backup.profiles)
        writeSettingsUnlocked(backup.settings)
    }

    fun save(profile: TunnelProfile) = transaction {
        val profiles = readProfilesUnlocked().filterNot { it.id == profile.id } + profile.copy(modifiedAt = System.currentTimeMillis())
        writeProfilesUnlocked(profiles)
        writeSettingsUnlocked(readSettingsUnlocked(profiles).copy(selectedProfileId = profile.id))
    }

    fun delete(id: String) = transaction {
        val profiles = readProfilesUnlocked().filterNot { it.id == id }
        writeProfilesUnlocked(profiles)
        writeSettingsUnlocked(readSettingsUnlocked(profiles))
    }

    fun settings(settings: AppSettings) = transaction {
        val selected = settings.selectedProfileId
        if (selected != null && selected != storedSettingsUnlocked().selectedProfileId)
            require(readProfilesUnlocked().any { it.id == selected }) { "Selected profile is missing" }
        writeSettingsUnlocked(settings)
    }

    fun export(password: CharArray): ByteArray {
        val clear = codec.encodeToString(read()).toByteArray()
        try { return BackupCodec.encrypt(clear, password) } finally { clear.fill(0) }
    }

    fun restore(data: ByteArray, password: CharArray) {
        val clear = BackupCodec.decrypt(data, password)
        try {
            val imported = decodeBackup(clear.toString(Charsets.UTF_8))
            transaction {
                val profiles = (readProfilesUnlocked() + imported.profiles).associateBy { it.id }.values.toList()
                writeProfilesUnlocked(profiles)
                writeSettingsUnlocked(imported.settings)
            }
        } finally { clear.fill(0) }
    }

    companion object {
        private val processLock = Any()
        private val PROFILE_CONTEXT = "sslsockspro.profile-storage.v1".toByteArray()
        private val SETTINGS_CONTEXT = "sslsockspro.settings.v2".toByteArray()
        // Newer releases may add fields; an unsupported format is still rejected.
        private val codec = Json { ignoreUnknownKeys = true; encodeDefaults = true }

        private fun requireSupported(format: Int) {
            require(format in 1..Backup.FORMAT) {
                if (format > Backup.FORMAT) "This data was created by a newer version of SSLSocks Pro" else "Unsupported storage format"
            }
        }

        /** Decodes a portable backup of any supported format. */
        fun decodeBackup(text: String): Backup {
            val backup = codec.decodeFromString<Backup>(text)
            requireSupported(backup.format)
            return backup.copy(format = Backup.FORMAT).also(::validate)
        }

        fun validate(backup: Backup) {
            requireSupported(backup.format)
            validateProfiles(backup.profiles)
            require(backup.settings.selectedProfileId == null || backup.profiles.any { it.id == backup.settings.selectedProfileId }) { "Selected profile is missing" }
        }

        private fun singleLine(value: String) = value.length <= 4096 && value.none { it == '\n' || it == '\r' || it == '\u0000' }

        private fun validateProfiles(profiles: List<TunnelProfile>) {
            require(profiles.size <= 128) { "Too many profiles" }
            require(profiles.map { it.id }.toSet().size == profiles.size) { "Duplicate profile IDs" }
            for (profile in profiles) {
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
                require(listOf(profile.openVpnUsername, profile.openVpnPassword, profile.openVpnKeyPassphrase,
                    profile.proxyUsername, profile.proxyPassword).all(::singleLine)) { "Invalid saved credentials" }
                require(profile.proxyUsername.length <= 255 && profile.proxyPassword.length <= 255) { "Proxy credentials exceed 255 characters" }
                require(profile.openVpnKeyAlias.isEmpty() || profile.openVpnKeyAlias.matches(Regex("sslsockspro\\.openvpn\\.[a-f0-9-]{36}"))) { "Invalid key alias" }
                require(profile.operatorKeyFingerprint.isEmpty() || profile.operatorKeyFingerprint.matches(Regex("[A-F0-9]{64}"))) { "Invalid operator fingerprint" }
            }
        }
    }
}
