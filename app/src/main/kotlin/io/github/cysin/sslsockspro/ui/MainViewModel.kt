package io.github.cysin.sslsockspro.ui

import android.app.Application
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import io.github.cysin.sslsockspro.TunnelApplication
import io.github.cysin.sslsockspro.config.StunnelDocument
import io.github.cysin.sslsockspro.data.CertificateSummary
import io.github.cysin.sslsockspro.data.Credentials
import io.github.cysin.sslsockspro.data.PackageImporter
import io.github.cysin.sslsockspro.data.PackageManifest
import io.github.cysin.sslsockspro.model.AppSettings
import io.github.cysin.sslsockspro.model.Backup
import io.github.cysin.sslsockspro.model.TunnelProfile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.Base64

/** Profiles, drafts and pending document results survive activity
 * recreation here, in memory. Credentials never enter saved-state bundles. */
class MainViewModel(application: Application) : AndroidViewModel(application) {
    private val store = (application as TunnelApplication).profiles

    var backup by mutableStateOf(Backup(profiles = emptyList())); private set
    var loading by mutableStateOf(true); private set
    var page by mutableIntStateOf(0)
    var error by mutableStateOf<String?>(null)
    var editor by mutableStateOf<TunnelProfile?>(null)
    var pendingConnect by mutableStateOf<TunnelProfile?>(null)
    var pendingNotification by mutableStateOf<TunnelProfile?>(null)
    var passwordAction by mutableStateOf<String?>(null)
    var password by mutableStateOf("")
    var pendingRestore by mutableStateOf<ByteArray?>(null)
    var pendingExport by mutableStateOf<ByteArray?>(null)
    /** Parsed package awaiting the user's confirmation of its origin. */
    var pendingImport by mutableStateOf<PackageImporter.ImportPlan?>(null)
    /** Per profile ID; recomputed only when that profile changes. */
    var certificates by mutableStateOf<Map<String, List<CertificateSummary>>>(emptyMap()); private set
    var tunnels by mutableStateOf<Map<String, List<String>>>(emptyMap()); private set
    private val summaries = mutableMapOf<String, Pair<Long, Pair<List<CertificateSummary>, List<String>>>>()

    val selected: TunnelProfile?
        get() = backup.profiles.firstOrNull { it.id == backup.settings.selectedProfileId } ?: backup.profiles.firstOrNull()

    init { refresh() }

    fun refresh(then: () -> Unit = {}) {
        viewModelScope.launch {
            try {
                backup = withContext(Dispatchers.IO) { store.read() }
                summarize()
                then()
            } catch (failure: Exception) { error = "Could not open encrypted profiles. ${failure.message.orEmpty()}" }
            finally { loading = false }
        }
    }

    private suspend fun summarize() {
        val profiles = backup.profiles
        val cache = summaries.toMap()
        val computed = withContext(Dispatchers.Default) {
            profiles.associate { profile ->
                val cached = cache[profile.id]?.takeIf { it.first == profile.modifiedAt }?.second
                profile.id to (cached ?: (Credentials.summaries(profile) to tunnelLines(profile)))
            }
        }
        summaries.keys.retainAll(computed.keys)
        profiles.forEach { summaries[it.id] = it.modifiedAt to computed.getValue(it.id) }
        certificates = computed.mapValues { it.value.first }
        tunnels = computed.mapValues { it.value.second }
    }

    private fun tunnelLines(profile: TunnelProfile): List<String> =
        if (profile.config.isBlank()) emptyList() else runCatching { StunnelDocument.parse(profile.config) }.getOrNull()?.let { document ->
            document.sections.map { section ->
                "[$section] ${runCatching { document.listener(section) }.getOrNull()} → ${document.remotes(section).firstOrNull()}"
            }
        }.orEmpty()

    private fun perform(failure: String, action: suspend () -> Unit) {
        viewModelScope.launch {
            try { action() } catch (problem: Exception) { error = problem.message ?: failure }
        }
    }

    fun updateSettings(transform: (AppSettings) -> AppSettings) = perform("Could not save settings") {
        withContext(Dispatchers.IO) { store.settings(transform(backup.settings)) }
        refresh()
    }

    fun select(id: String, then: () -> Unit = {}) = perform("Could not select profile") {
        withContext(Dispatchers.IO) { store.settings(backup.settings.copy(selectedProfileId = id)) }
        refresh(then)
    }

    fun save(profile: TunnelProfile) = perform("Could not save profile") {
        // An edited configuration or credential set is no longer what the operator signed.
        val stored = backup.profiles.firstOrNull { it.id == profile.id }
        val signed = stored != null && stored.config == profile.config && stored.openVpnConfig == profile.openVpnConfig && stored.files == profile.files
        val saved = if (signed) profile else profile.copy(operatorKeyFingerprint = "")
        withContext(Dispatchers.IO) { store.save(saved) }
        editor = null
        refresh()
    }

    fun delete(id: String) = perform("Could not delete profile") {
        withContext(Dispatchers.IO) { store.delete(id) }
        refresh()
    }

    /** Attaches imported files to the open draft, or creates profiles. */
    fun import(files: Map<String, ByteArray>) = perform("Could not import files") {
        if (files.isEmpty()) return@perform
        val draft = editor
        if (draft != null) {
            editor = draft.copy(files = draft.files + files.filterKeys {
                !it.endsWith(".conf", true) && !it.endsWith(".ovpn", true) && it !in PackageManifest.NAMES
            }
                .mapValues { Base64.getEncoder().encodeToString(it.value) },
                openVpnConfig = files.filterKeys { it.endsWith(".ovpn", true) }.values.firstOrNull()?.toString(Charsets.UTF_8) ?: draft.openVpnConfig)
            return@perform
        }
        val plan = withContext(Dispatchers.IO) { PackageImporter.plan(files) }
        require(plan.profiles.isNotEmpty()) { "Select a client configuration/package, or open a profile to attach credentials" }
        pendingImport = plan
    }

    /** Files from another app: only whole profiles, always confirmed. */
    fun importShared(files: Map<String, ByteArray>) = perform("Could not import files") {
        if (files.isEmpty()) return@perform
        val plan = withContext(Dispatchers.IO) { PackageImporter.plan(files) }
        require(plan.profiles.isNotEmpty()) { "The shared files contain no client configuration. To add credentials, open a profile and attach them there." }
        pendingImport = plan
    }

    fun confirmImport() = perform("Could not import files") {
        val plan = pendingImport ?: return@perform
        pendingImport = null
        withContext(Dispatchers.IO) { plan.profiles.forEach(store::save) }
        refresh { page = 1 }
    }

    fun exportBackup(characters: CharArray, then: () -> Unit) {
        viewModelScope.launch {
            try { pendingExport = withContext(Dispatchers.IO) { store.export(characters) }; then() }
            catch (_: Exception) { error = "Backup could not be processed. Check the password and file integrity." }
            finally { characters.fill('\u0000') }
        }
    }

    fun restoreBackup(characters: CharArray) {
        viewModelScope.launch {
            val data = pendingRestore
            try {
                require(data != null) { "Backup file is missing" }
                withContext(Dispatchers.IO) { store.restore(data, characters) }
                refresh()
            } catch (_: Exception) { error = "Backup could not be processed. Check the password and file integrity." }
            finally { characters.fill('\u0000'); data?.fill(0); pendingRestore = null }
        }
    }

    fun discardPending() {
        pendingRestore?.fill(0); pendingRestore = null
        pendingExport?.fill(0); pendingExport = null
    }

    override fun onCleared() {
        discardPending()
        password = ""; editor = null; pendingImport = null
        pendingConnect = null; pendingNotification = null
    }
}
