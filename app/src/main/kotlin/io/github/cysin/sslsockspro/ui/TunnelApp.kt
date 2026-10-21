package io.github.cysin.sslsockspro.ui

import android.Manifest
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.content.Intent
import android.provider.OpenableColumns
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import io.github.cysin.sslsockspro.config.StunnelDocument
import io.github.cysin.sslsockspro.data.PackageImporter
import io.github.cysin.sslsockspro.data.PackageManifest
import io.github.cysin.sslsockspro.model.ConnectionMode
import io.github.cysin.sslsockspro.model.TunnelProfile
import io.github.cysin.sslsockspro.service.ConnectionService
import io.github.cysin.sslsockspro.service.TunnelState
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun TunnelApp(incoming: MutableStateFlow<Intent?>) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val ui: MainViewModel = viewModel()
    // Only the profile ID is saved across recreation, never its credentials.
    var deleteCandidate by rememberSaveable { mutableStateOf<String?>(null) }

    fun filename(uri: Uri): String {
        context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
            if (cursor.moveToFirst()) return cursor.getString(0)
        }
        return "import.conf"
    }
    /** Reads selected documents within import limits; overlapping names must agree. */
    suspend fun read(uris: List<Uri>): Map<String, ByteArray> = withContext(Dispatchers.IO) {
        val combined = linkedMapOf<String, ByteArray>()
        for (uri in uris) {
            val bytes = context.contentResolver.openInputStream(uri)?.use { PackageImporter.boundedRead(it, PackageImporter.MAX_TOTAL) } ?: continue
            PackageImporter.entries(bytes, filename(uri)).forEach { (name, data) ->
                require(combined[name] == null || combined[name]!!.contentEquals(data)) { "Choose one client package at a time when credential filenames overlap" }
                combined[name] = data
            }
            require(combined.size <= 128 && combined.values.sumOf { it.size.toLong() } <= PackageImporter.MAX_TOTAL) { "Selected files exceed import limits" }
        }
        combined
    }
    val importFiles = rememberLauncherForActivityResult(ActivityResultContracts.GetMultipleContents()) { uris ->
        scope.launch {
            try { ui.import(read(uris)) } catch (failure: Exception) { ui.error = failure.message ?: "Could not import files" }
        }
    }
    // Opened or shared by another app: always confirmed, never attached to a draft.
    LaunchedEffect(incoming) {
      incoming.consumePending { intent ->
        val uris = when (intent.action) {
            Intent.ACTION_VIEW -> listOfNotNull(intent.data)
            Intent.ACTION_SEND -> listOfNotNull(intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java))
            Intent.ACTION_SEND_MULTIPLE -> intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM, Uri::class.java).orEmpty()
            else -> emptyList()
        }.filter { it.scheme == "content" }
        if (uris.isEmpty()) return@consumePending
        try {
            if (uris.size == 1 && filename(uris.single()).endsWith(".sspbackup", ignoreCase = true)) {
                require(!TunnelState.status.value.running) { "Disconnect before restoring a backup." }
                ui.pendingRestore = withContext(Dispatchers.IO) {
                    context.contentResolver.openInputStream(uris.single())!!.use { PackageImporter.boundedRead(it, 32 * 1024 * 1024 + 52) }
                }
                ui.password = ""; ui.passwordAction = "restore"
            } else ui.importShared(read(uris))
        } catch (cancelled: CancellationException) { throw cancelled }
        catch (failure: Exception) { ui.error = failure.message ?: "Could not open the shared files" }
      }
    }
    val restoreFile = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri != null) scope.launch {
            try {
                ui.pendingRestore = withContext(Dispatchers.IO) { context.contentResolver.openInputStream(uri)!!.use { PackageImporter.boundedRead(it, 32 * 1024 * 1024 + 52) } }
                ui.password = ""; ui.passwordAction = "restore"
            } catch (failure: Exception) { ui.error = failure.message ?: "Could not read backup" }
        }
    }
    val exportFile = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        if (uri != null) scope.launch {
            val content = ui.pendingExport
            try {
                require(content != null)
                withContext(Dispatchers.IO) { context.contentResolver.openOutputStream(uri, "wt")!!.use { it.write(content) } }
            } catch (failure: Exception) { ui.error = failure.message ?: "Could not save backup" }
            finally { ui.discardPending() }
        } else ui.discardPending()
    }
    val exportLogs = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("text/plain")) { uri ->
        if (uri != null) scope.launch {
            try {
                val content = TunnelState.logs.value.joinToString("\n").toByteArray()
                withContext(Dispatchers.IO) { context.contentResolver.openOutputStream(uri, "wt")!!.use { it.write(content) } }
            } catch (failure: Exception) { ui.error = failure.message ?: "Could not export diagnostics" }
        }
    }
    val vpnPermission = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        val profile = ui.pendingConnect
        ui.pendingConnect = null
        if (result.resultCode == android.app.Activity.RESULT_OK && profile != null) ConnectionService.start(context, profile)
        else ui.error = "VPN permission was not granted. No phone-wide protection was started."
    }
    fun startWithVpnPermission(profile: TunnelProfile) {
        if (profile.mode != ConnectionMode.LOCAL_PROXY) {
            val intent = VpnService.prepare(context)
            if (intent != null) { ui.pendingConnect = profile; vpnPermission.launch(intent); return }
        }
        ConnectionService.start(context, profile)
    }
    val notifications = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {
        ui.pendingNotification?.let(::startWithVpnPermission)
        ui.pendingNotification = null
    }
    // Permission dialogs are sequenced: notifications first, then VPN consent.
    fun connect(profile: TunnelProfile) {
        if (context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            ui.pendingNotification = profile
            notifications.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else startWithVpnPermission(profile)
    }

    BackHandler(enabled = ui.page != 0 && ui.editor == null) { ui.page = 0 }
    val dark = ui.backup.settings.darkTheme ?: isSystemInDarkTheme()
    MaterialTheme(colorScheme = if (dark) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)) {
        Scaffold(
            topBar = { TopAppBar(title = { Text("SSLSocks Pro") }, actions = {
                IconButton(onClick = { importFiles.launch("*/*") }) { Icon(Icons.Default.FileOpen, "Import client configuration") }
            }) },
            bottomBar = { NavigationBar {
                val titles = listOf("Connection", "Profiles", "Certificates", "Logs", "Settings")
                val labels = listOf("Status", "Profiles", "Certs", "Logs", "Settings")
                val icons = listOf(Icons.Default.Shield, Icons.Default.Folder, Icons.Default.VpnKey, Icons.AutoMirrored.Filled.List, Icons.Default.Settings)
                titles.forEachIndexed { index, title -> NavigationBarItem(selected = ui.page == index, onClick = { ui.page = index },
                    icon = { Icon(icons[index], title) }, label = { Text(labels[index], maxLines = 1, overflow = TextOverflow.Ellipsis) }) }
            } },
            floatingActionButton = {
                if (ui.page == 1) FloatingActionButton(onClick = { ui.editor = TunnelProfile(name = "New server", config = StunnelDocument.template()) }) {
                    Icon(Icons.Default.Add, "Create profile")
                }
            }
        ) { padding ->
            if (ui.loading) Box(Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) { CircularProgressIndicator() }
            else when (ui.page) {
                0 -> StatusScreen(ui, padding, onConnect = ::connect, onImport = { importFiles.launch("*/*") })
                1 -> ProfilesScreen(ui, padding, onDelete = { deleteCandidate = it.id })
                2 -> CertificatesScreen(ui, padding)
                3 -> LogsScreen(padding, onExport = { exportLogs.launch("sslsockspro-diagnostics.txt") })
                4 -> SettingsScreen(ui, padding, onRestore = { restoreFile.launch("application/octet-stream") })
            }
        }
        ui.editor?.let { profile ->
            ProfileEditor(profile, onChange = { ui.editor = it }, onImport = { importFiles.launch("*/*") }, onDismiss = { ui.editor = null }, onSave = ui::save)
        }
        deleteCandidate?.let { id -> ui.backup.profiles.firstOrNull { it.id == id } }?.let { profile ->
            AlertDialog(onDismissRequest = { deleteCandidate = null },
                title = { Text("Delete ${profile.name}?") },
                text = { Text("Its configuration and private credentials are permanently removed from this phone. An encrypted backup is the only way to restore them.") },
                confirmButton = { TextButton(onClick = { deleteCandidate = null; ui.delete(profile.id) }) { Text("Delete") } },
                dismissButton = { TextButton(onClick = { deleteCandidate = null }) { Text("Cancel") } })
        }
        ui.pendingImport?.let { plan ->
            val count = plan.profiles.size
            AlertDialog(onDismissRequest = { ui.pendingImport = null },
                title = { Text(if (count == 1) "Import ${plan.profiles.single().name}?" else "Import $count profiles?") },
                text = { Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    val fingerprint = plan.operatorFingerprint
                    if (fingerprint != null) {
                        Text("Signed by the operator key with SHA-256 fingerprint:")
                        Text(PackageManifest.display(fingerprint), fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
                        Text("Compare it with the fingerprint your server operator gave you through another channel.")
                    } else Text("This package is not signed. Import it only if you received it directly from your server operator.",
                        color = MaterialTheme.colorScheme.error)
                } },
                confirmButton = { TextButton(onClick = ui::confirmImport) { Text("Import") } },
                dismissButton = { TextButton(onClick = { ui.pendingImport = null }) { Text("Cancel") } })
        }
        val challenge by TunnelState.challenge.collectAsStateWithLifecycle()
        challenge?.let { prompt ->
            var code by remember(prompt) { mutableStateOf("") }
            AlertDialog(onDismissRequest = { },
                title = { Text("Verification code") },
                text = { Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text(prompt.text.ifBlank { "Your OpenVPN server asks for a code." })
                    SecureTextField(code, { code = it }, "Code", Modifier.fillMaxWidth(), secret = !prompt.echo)
                } },
                confirmButton = { TextButton(onClick = { TunnelState.answerChallenge(code); code = "" }) { Text("Send") } },
                dismissButton = { TextButton(onClick = { TunnelState.challenge(null); ConnectionService.stop(context) }) { Text("Disconnect") } })
        }
        ui.error?.let { message ->
            AlertDialog(onDismissRequest = { ui.error = null }, title = { Text("Action needs attention") }, text = { Text(message) },
                confirmButton = { TextButton(onClick = { ui.error = null }) { Text("OK") } })
        }
        ui.passwordAction?.let { action ->
            fun cancel() { ui.password = ""; ui.passwordAction = null; ui.discardPending() }
            AlertDialog(onDismissRequest = ::cancel,
                title = { Text(if (action == "export") "Encrypt backup" else "Unlock backup") },
                text = { Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text("Use at least 12 characters. This password protects every profile and private key in the backup.")
                    SecureTextField(ui.password, { ui.password = it }, "Backup password", Modifier.fillMaxWidth(), secret = true)
                } },
                confirmButton = { TextButton(enabled = ui.password.length >= 12, onClick = {
                    val characters = ui.password.toCharArray(); ui.password = ""; ui.passwordAction = null
                    if (action == "export") ui.exportBackup(characters) { exportFile.launch("sslsockspro-backup.sspbackup") }
                    else ui.restoreBackup(characters)
                }) { Text(if (action == "export") "Encrypt and save" else "Restore") } },
                dismissButton = { TextButton(onClick = ::cancel) { Text("Cancel") } })
        }
    }
}
