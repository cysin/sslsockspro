package io.github.cysin.sslsockspro.ui

import android.Manifest
import android.content.Intent
import android.net.Uri
import android.net.VpnService
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Bundle
import android.provider.OpenableColumns
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import io.github.cysin.sslsockspro.TunnelApplication
import io.github.cysin.sslsockspro.config.StunnelDocument
import io.github.cysin.sslsockspro.data.Credentials
import io.github.cysin.sslsockspro.data.PackageImporter
import io.github.cysin.sslsockspro.model.Backup
import io.github.cysin.sslsockspro.model.ConnectionMode
import io.github.cysin.sslsockspro.model.ConnectionStage
import io.github.cysin.sslsockspro.model.ProxyKind
import io.github.cysin.sslsockspro.model.TunnelProfile
import io.github.cysin.sslsockspro.service.ConnectionService
import io.github.cysin.sslsockspro.service.TunnelState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Base64

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent { TunnelApp() }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun TunnelApp() {
    val context = LocalContext.current
    val store = (context.applicationContext as TunnelApplication).profiles
    val scope = rememberCoroutineScope()
    val ui: TunnelUiState = viewModel()
    var backup by ui.backup
    var loading by ui.loading
    var page by ui.page
    var error by ui.error
    var editor by ui.editor
    var pendingConnect by ui.pendingConnect
    var passwordAction by ui.passwordAction
    var password by ui.password
    var pendingRestore by ui.pendingRestore
    var pendingExport by ui.pendingExport
    var pendingNotification by ui.pendingNotification
    // Only the profile ID is saved across recreation, never its credentials.
    var deleteCandidate by rememberSaveable { mutableStateOf<String?>(null) }
    val status by TunnelState.status.collectAsStateWithLifecycle()
    val logs by TunnelState.logs.collectAsStateWithLifecycle()
    val selected = backup.profiles.firstOrNull { it.id == backup.settings.selectedProfileId } ?: backup.profiles.firstOrNull()
    val active = status.running
    val displayedProfile = backup.profiles.firstOrNull { active && it.id == status.profileId } ?: selected
    val certificateSummaries by produceState<Map<String, List<io.github.cysin.sslsockspro.data.CertificateSummary>>>(emptyMap(), backup.profiles) {
        value = withContext(Dispatchers.IO) { backup.profiles.associate { it.id to Credentials.summaries(it) } }
    }

    fun refresh() { scope.launch {
        try { backup = withContext(Dispatchers.IO) { store.read() } }
        catch (failure: Exception) { error = "Could not open encrypted profiles. ${failure.message.orEmpty()}" }
        finally { loading = false }
    } }
    LaunchedEffect(Unit) { refresh() }

    fun filename(uri: Uri): String {
        context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
            if (cursor.moveToFirst()) return cursor.getString(0)
        }
        return "import.conf"
    }
    val importFiles = rememberLauncherForActivityResult(ActivityResultContracts.GetMultipleContents()) { uris ->
        scope.launch {
            try {
                val files = withContext(Dispatchers.IO) {
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
                if (files.isNotEmpty()) {
                    val draft = editor
                    if (draft != null) {
                        editor = draft.copy(files = draft.files + files.filterKeys { !it.endsWith(".conf", true) && !it.endsWith(".ovpn", true) }
                            .mapValues { Base64.getEncoder().encodeToString(it.value) },
                            openVpnConfig = files.filterKeys { it.endsWith(".ovpn", true) }.values.firstOrNull()?.toString(Charsets.UTF_8) ?: draft.openVpnConfig)
                    } else {
                        val profiles = withContext(Dispatchers.IO) { PackageImporter.profiles(files) }
                        require(profiles.isNotEmpty()) { "Select a client configuration/package, or open a profile to attach credentials" }
                        withContext(Dispatchers.IO) { profiles.forEach(store::save) }
                        refresh(); page = 1
                    }
                }
            } catch (failure: Exception) { error = failure.message ?: "Could not import files" }
        }
    }
    val restoreFile = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri != null) scope.launch {
            try {
                pendingRestore = withContext(Dispatchers.IO) { context.contentResolver.openInputStream(uri)!!.use { PackageImporter.boundedRead(it, 32 * 1024 * 1024 + 52) } }
                password = ""; passwordAction = "restore"
            } catch (failure: Exception) { error = failure.message ?: "Could not read backup" }
        }
    }
    val exportFile = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        if (uri != null) scope.launch {
            val content = pendingExport
            try {
                require(content != null)
                withContext(Dispatchers.IO) { context.contentResolver.openOutputStream(uri, "wt")!!.use { it.write(content) } }
            } catch (failure: Exception) { error = failure.message ?: "Could not save backup" }
            finally { content?.fill(0); pendingExport = null }
        } else { pendingExport?.fill(0); pendingExport = null }
    }
    val exportLogs = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("text/plain")) { uri ->
        if (uri != null) scope.launch {
            try {
                val content = TunnelState.logs.value.joinToString("\n").toByteArray()
                withContext(Dispatchers.IO) { context.contentResolver.openOutputStream(uri, "wt")!!.use { it.write(content) } }
            } catch (failure: Exception) { error = failure.message ?: "Could not export diagnostics" }
        }
    }
    val vpnPermission = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        val profile = pendingConnect
        pendingConnect = null
        if (result.resultCode == android.app.Activity.RESULT_OK && profile != null) ConnectionService.start(context, profile)
        else error = "VPN permission was not granted. No phone-wide protection was started."
    }
    fun startWithVpnPermission(profile: TunnelProfile) {
        if (profile.mode != ConnectionMode.LOCAL_PROXY) {
            val intent = VpnService.prepare(context)
            if (intent != null) { pendingConnect = profile; vpnPermission.launch(intent); return }
        }
        ConnectionService.start(context, profile)
    }
    val notifications = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {
        pendingNotification?.let(::startWithVpnPermission)
        pendingNotification = null
    }
    fun connect(profile: TunnelProfile) {
        if (context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
            pendingNotification = profile
            notifications.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else startWithVpnPermission(profile)
    }

    val manager = remember { context.getSystemService(ConnectivityManager::class.java) }
    var captiveNetwork by remember { mutableStateOf<Network?>(null) }
    var strictPrivateDns by remember { mutableStateOf(false) }
    DisposableEffect(manager) {
        fun update() {
            val networks = manager.allNetworks.filter { network ->
                manager.getNetworkCapabilities(network)?.let { !it.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                    it.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) } == true
            }
            captiveNetwork = networks.firstOrNull { manager.getNetworkCapabilities(it)?.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL) == true }
            strictPrivateDns = networks.any { !manager.getLinkProperties(it)?.privateDnsServerName.isNullOrBlank() }
        }
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) { update() }
            override fun onLost(network: Network) { update() }
            override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) { update() }
            override fun onLinkPropertiesChanged(network: Network, properties: android.net.LinkProperties) { update() }
        }
        update()
        manager.registerNetworkCallback(NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(), callback)
        onDispose { manager.unregisterNetworkCallback(callback) }
    }

    val dark = backup.settings.darkTheme ?: isSystemInDarkTheme()
    MaterialTheme(colorScheme = if (dark) darkColorScheme() else lightColorScheme()) {
        Scaffold(
            topBar = { TopAppBar(title = { Text("SSLSocks Pro") }, actions = {
                IconButton(onClick = { importFiles.launch("*/*") }) { Icon(Icons.Default.FileOpen, "Import client configuration") }
            }) },
            bottomBar = { NavigationBar {
                val titles = listOf("Connection", "Profiles", "Certificates", "Logs", "Settings")
                val labels = listOf("Status", "Profiles", "Certs", "Logs", "Settings")
                val icons = listOf(Icons.Default.Shield, Icons.Default.Folder, Icons.Default.VpnKey, Icons.Default.List, Icons.Default.Settings)
                titles.forEachIndexed { index, title -> NavigationBarItem(selected = page == index, onClick = { page = index },
                    icon = { Icon(icons[index], title) }, label = { Text(labels[index], maxLines = 1, overflow = TextOverflow.Ellipsis) }) }
            } },
            floatingActionButton = {
                if (page == 1) FloatingActionButton(onClick = { editor = TunnelProfile(name = "New server", config = StunnelDocument.template()) }) {
                    Icon(Icons.Default.Add, "Create profile")
                }
            }
        ) { padding ->
            if (loading) Box(Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) { CircularProgressIndicator() }
            else when (page) {
                0 -> Column(Modifier.padding(padding).padding(20.dp).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(18.dp)) {
                    Text("Your connection", style = MaterialTheme.typography.headlineMedium)
                    ElevatedCard(Modifier.fillMaxWidth()) { Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(if (status.stage == ConnectionStage.CONNECTED) Icons.Default.VerifiedUser else Icons.Default.Shield, null)
                            Spacer(Modifier.width(12.dp))
                            Text(stageLabel(status.stage), style = MaterialTheme.typography.titleLarge)
                        }
                        Text(status.message)
                        if (displayedProfile?.mode == ConnectionMode.PROXY_VPN) Text(
                            if (displayedProfile.proxyIpv6) "IPv4 and IPv6 destinations enabled" else "IPv4 destinations; IPv6 blocked")
                        if (displayedProfile != null) {
                            Text(displayedProfile.name, style = MaterialTheme.typography.titleMedium)
                            Text(modeLabel(displayedProfile.mode), style = MaterialTheme.typography.bodyMedium)
                            if (!active && backup.profiles.size > 1) ProfileSelector(backup.profiles, displayedProfile.id) { id ->
                                scope.launch { withContext(Dispatchers.IO) { store.settings(backup.settings.copy(selectedProfileId = id)) }; refresh() }
                            }
                        } else Text("Import a client package with its certificates to get started.")
                        Button(onClick = { if (active) ConnectionService.stop(context) else selected?.let(::connect) }, enabled = !status.alwaysOn && status.stage != ConnectionStage.STOPPING && (active || selected != null),
                            modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp)) {
                            Text(if (status.alwaysOn) "Controlled by Android always-on VPN" else if (status.stage == ConnectionStage.STOPPING) "Disconnecting…" else if (active) "Disconnect" else "Connect")
                        }
                        if (selected == null) OutlinedButton(onClick = { importFiles.launch("*/*") }, modifier = Modifier.fillMaxWidth()) { Text("Import client package") }
                    } }
                    if (displayedProfile != null) {
                        Text(if (displayedProfile.mode == ConnectionMode.LOCAL_PROXY) "Local proxy mode covers apps configured to use the listener. It does not route the whole phone."
                            else if (displayedProfile.mode == ConnectionMode.PROXY_VPN) "TCP and encrypted DNS use your server. Other UDP, including QUIC, is blocked. No direct fallback."
                            else "An OpenVPN server and a valid .ovpn profile are required. Your stunnel proxy can carry the OpenVPN TCP connection.")
                        if (displayedProfile.includedApps.isNotEmpty()) Text("Coverage: ${displayedProfile.includedApps.size} selected " +
                            (if (displayedProfile.includedApps.size == 1) "app." else "apps.") + " Android block-without-VPN settings may block other apps.")
                        certificateSummaries[displayedProfile.id].orEmpty().filter { it.clientIdentity }.minByOrNull { it.expires }?.let { certificate ->
                            val days = (certificate.expires - System.currentTimeMillis()) / 86_400_000
                            if (days < 30) Text("Client certificate expires ${date(certificate.expires)}. Import its replacement before expiry.", color = MaterialTheme.colorScheme.error)
                        }
                        Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                            Text("Sent ${bytes(status.bytesSent)}")
                            Text("Received ${bytes(status.bytesReceived)}")
                        }
                    }
                    if (captiveNetwork != null) {
                        Text("This hotspot requires sign-in. Finish sign-in before connecting; the app will not bypass a blocked VPN.", color = MaterialTheme.colorScheme.error)
                        OutlinedButton(onClick = { context.startActivity(Intent(Settings.ACTION_WIFI_SETTINGS)) }) { Text("Open Wi-Fi sign-in settings") }
                    }
                    if (strictPrivateDns && selected?.mode == ConnectionMode.PROXY_VPN) Text(
                        "Set Android Private DNS to Automatic or Off. This VPN supplies DNS-over-HTTPS through your tunnel and never falls back to direct DNS.",
                        color = MaterialTheme.colorScheme.error)
                    OutlinedButton(onClick = { context.startActivity(Intent(Settings.ACTION_VPN_SETTINGS)) }) { Text("Always-on and block-without-VPN settings") }
                    OutlinedButton(onClick = { context.startActivity(Intent(Settings.ACTION_WIFI_SETTINGS)) }) { Text("Wi-Fi and hotspot sign-in") }
                }
                1 -> LazyColumn(Modifier.padding(padding).padding(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(12.dp), contentPadding = PaddingValues(bottom = 100.dp, top = 12.dp)) {
                    if (backup.profiles.isEmpty()) item { Text("No profiles yet. Import your stunnel client package or create a profile.") }
                    items(backup.profiles, key = { it.id }) { profile -> ElevatedCard(Modifier.fillMaxWidth()) { Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text(profile.name, style = MaterialTheme.typography.titleLarge)
                        Text(modeLabel(profile.mode))
                        if (profile.config.isNotBlank()) runCatching { StunnelDocument.parse(profile.config) }.getOrNull()?.let { document ->
                            document.sections.forEach { section -> Text("[$section] ${document.listener(section)} → ${document.remotes(section).firstOrNull()}", maxLines = 2, overflow = TextOverflow.Ellipsis) }
                        }
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            TextButton(onClick = { scope.launch { withContext(Dispatchers.IO) { store.settings(backup.settings.copy(selectedProfileId = profile.id)) }; refresh(); page = 0 } }) { Text("Select") }
                            TextButton(enabled = status.profileId != profile.id || !active, onClick = { editor = profile }) { Text("Edit") }
                            TextButton(enabled = status.profileId != profile.id || !active, onClick = { deleteCandidate = profile.id }) { Text("Delete") }
                        }
                    } } }
                }
                2 -> LazyColumn(Modifier.padding(padding).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    item { Text("Certificates stay in encrypted private app storage. Private keys are never displayed here.") }
                    items(backup.profiles.flatMap { profile -> certificateSummaries[profile.id].orEmpty().map { profile.name to it } }) { (name, certificate) ->
                        OutlinedCard(Modifier.fillMaxWidth()) { Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text(name, style = MaterialTheme.typography.titleMedium)
                            Text(certificate.name)
                            Text(certificate.subject)
                            Text("Expires ${date(certificate.expires)}", color = if (certificate.expires < System.currentTimeMillis()) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface)
                            Text("SHA-256 ${certificate.fingerprint}", style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
                        } }
                    }
                    item { OutlinedButton(enabled = !active || selected?.id != status.profileId, onClick = { selected?.let { editor = it } }) { Text("Manage files in selected profile") } }
                }
                3 -> Column(Modifier.padding(padding).padding(16.dp)) {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text("Connection log", style = MaterialTheme.typography.titleLarge)
                        TextButton(onClick = TunnelState::clearLogs) { Text("Clear") }
                    }
                    Text("Bounded diagnostics; no traffic payloads or automatic uploads.", style = MaterialTheme.typography.bodySmall)
                    TextButton(onClick = { exportLogs.launch("sslsockspro-diagnostics.txt") }) { Text("Save redacted diagnostics") }
                    LazyColumn(Modifier.weight(1f)) { items(logs) { Text(it, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(vertical = 4.dp)) } }
                }
                4 -> Column(Modifier.padding(padding).padding(20.dp).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                    Text("Settings", style = MaterialTheme.typography.headlineMedium)
                    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                        Text("Reconnect after network failures", Modifier.weight(1f))
                        Switch(backup.settings.reconnect, onCheckedChange = { enabled -> scope.launch { withContext(Dispatchers.IO) { store.settings(backup.settings.copy(reconnect = enabled)) }; refresh() } })
                    }
                    Text("Appearance", style = MaterialTheme.typography.titleMedium)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        listOf("System" to null, "Light" to false, "Dark" to true).forEach { (label, value) ->
                            FilterChip(selected = backup.settings.darkTheme == value, onClick = {
                                scope.launch { withContext(Dispatchers.IO) { store.settings(backup.settings.copy(darkTheme = value)) }; refresh() }
                            }, label = { Text(label) })
                        }
                    }
                    OutlinedButton(onClick = { password = ""; passwordAction = "export" }, enabled = backup.profiles.isNotEmpty()) { Text("Create encrypted local backup") }
                    OutlinedButton(enabled = !active, onClick = { restoreFile.launch("application/octet-stream") }) { Text("Restore encrypted local backup") }
                    Text("Backups include private credentials and require your password. Keep the password separately; it cannot be recovered.")
                    HorizontalDivider()
                    Text("Components", style = MaterialTheme.typography.titleLarge)
                    var versions by remember { mutableStateOf("") }
                    LaunchedEffect(Unit) { versions = withContext(Dispatchers.IO) { runCatching { context.assets.open("native-versions.json").bufferedReader().use { it.readText() } }.getOrDefault("Native components are not packaged yet.") } }
                    Text(versions, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
                    Text("Android 16+ · ARM64 · SSLSocks Pro ${io.github.cysin.sslsockspro.BuildConfig.VERSION_NAME}")
                    var licenses by remember { mutableStateOf("") }
                    LaunchedEffect(Unit) { licenses = withContext(Dispatchers.IO) { context.assets.open("THIRD_PARTY_NOTICES.txt").bufferedReader().use { it.readText() } } }
                    Text(licenses, style = MaterialTheme.typography.bodySmall)
                    Text("Network routing does not hide account identity, device permissions, or data you give to other apps.")
                }
            }
        }
        editor?.let { profile -> ProfileEditor(profile, onChange = { editor = it }, onImport = { importFiles.launch("*/*") }, onDismiss = { editor = null }, onSave = { value ->
            scope.launch {
                try { withContext(Dispatchers.IO) { store.save(value) }; editor = null; refresh() }
                catch (failure: Exception) { error = failure.message ?: "Could not save profile" }
            }
        }) }
        deleteCandidate?.let { id -> backup.profiles.firstOrNull { it.id == id } }?.let { profile ->
            AlertDialog(onDismissRequest = { deleteCandidate = null },
                title = { Text("Delete ${profile.name}?") },
                text = { Text("Its configuration and private credentials are permanently removed from this phone. An encrypted backup is the only way to restore them.") },
                confirmButton = { TextButton(onClick = {
                    deleteCandidate = null
                    scope.launch {
                        try { withContext(Dispatchers.IO) { store.delete(profile.id) }; refresh() }
                        catch (failure: Exception) { error = failure.message ?: "Could not delete profile" }
                    }
                }) { Text("Delete") } },
                dismissButton = { TextButton(onClick = { deleteCandidate = null }) { Text("Cancel") } })
        }
        error?.let { message -> AlertDialog(onDismissRequest = { error = null }, title = { Text("Action needs attention") }, text = { Text(message) }, confirmButton = { TextButton(onClick = { error = null }) { Text("OK") } }) }
        passwordAction?.let { action -> AlertDialog(onDismissRequest = { password = ""; passwordAction = null; pendingRestore?.fill(0); pendingRestore = null },
            title = { Text(if (action == "export") "Encrypt backup" else "Unlock backup") },
            text = { Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("Use at least 12 characters. This password protects every profile and private key in the backup.")
                OutlinedTextField(password, onValueChange = { password = it }, label = { Text("Backup password") }, singleLine = true, visualTransformation = PasswordVisualTransformation())
            } }, confirmButton = { TextButton(enabled = password.length >= 12, onClick = {
                val characters = password.toCharArray(); password = ""; passwordAction = null
                scope.launch {
                    try {
                        if (action == "export") {
                            pendingExport = withContext(Dispatchers.IO) { store.export(characters) }
                            exportFile.launch("sslsockspro-backup.sspbackup")
                        } else {
                            val data = pendingRestore ?: error("Backup file is missing")
                            withContext(Dispatchers.IO) { store.restore(data, characters) }
                            data.fill(0); pendingRestore = null; refresh()
                        }
                    } catch (_: Exception) { error = "Backup could not be processed. Check the password and file integrity." }
                    finally { characters.fill('\u0000'); pendingRestore?.fill(0); pendingRestore = null }
                }
            }) { Text(if (action == "export") "Encrypt and save" else "Restore") } },
            dismissButton = { TextButton(onClick = { password = ""; passwordAction = null; pendingRestore?.fill(0); pendingRestore = null }) { Text("Cancel") } }) }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable private fun ProfileSelector(profiles: List<TunnelProfile>, selected: String, onSelect: (String) -> Unit) {
    var expanded by remember { mutableStateOf(false) }
    Box {
        OutlinedButton(onClick = { expanded = true }) { Text("Choose profile") }
        DropdownMenu(expanded, onDismissRequest = { expanded = false }) {
            profiles.forEach { profile -> DropdownMenuItem(text = { Text(profile.name) }, onClick = { onSelect(profile.id); expanded = false }) }
        }
    }
}


internal fun modeLabel(mode: ConnectionMode) = when (mode) { ConnectionMode.LOCAL_PROXY -> "Local proxy"; ConnectionMode.PROXY_VPN -> "Phone VPN through stunnel"; ConnectionMode.OPENVPN -> "Built-in OpenVPN" }
private fun stageLabel(stage: ConnectionStage) = when (stage) {
    ConnectionStage.IDLE -> "Disconnected"; ConnectionStage.VALIDATING -> "Validating"; ConnectionStage.CONNECTING -> "Connecting"
    ConnectionStage.LISTENING -> "Local proxy ready"; ConnectionStage.CONNECTED -> "Connected"; ConnectionStage.RECONNECTING -> "Reconnecting"
    ConnectionStage.STOPPING -> "Stopping"; ConnectionStage.ERROR -> "Needs attention"
}
private fun date(milliseconds: Long) = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm z").format(Instant.ofEpochMilli(milliseconds).atZone(ZoneId.systemDefault()))
private fun bytes(value: Long): String = when { value >= 1024 * 1024 -> "%.1f MiB".format(value / 1048576.0); value >= 1024 -> "%.1f KiB".format(value / 1024.0); else -> "$value B" }
