package io.github.cysin.sslsockspro.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import io.github.cysin.sslsockspro.BuildConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

@Composable
internal fun SettingsScreen(ui: MainViewModel, padding: PaddingValues, onRestore: () -> Unit) {
    val context = LocalContext.current
    val status by rememberConnectionActivity()
    val settings = ui.backup.settings
    Column(Modifier.padding(padding).padding(20.dp).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Text("Settings", style = MaterialTheme.typography.headlineMedium)
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Text("Reconnect after network failures", Modifier.weight(1f))
            Switch(settings.reconnect, onCheckedChange = { enabled -> ui.updateSettings { it.copy(reconnect = enabled) } })
        }
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Text("Start the selected local proxy after the phone restarts", Modifier.weight(1f))
            Switch(settings.bootStartLocalProxy, onCheckedChange = { enabled -> ui.updateSettings { it.copy(bootStartLocalProxy = enabled) } })
        }
        Text("VPN profiles start at boot through Android's always-on VPN setting instead, which also blocks traffic until the tunnel is ready.",
            style = MaterialTheme.typography.bodySmall)
        Text("Appearance", style = MaterialTheme.typography.titleMedium)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            listOf("System" to null, "Light" to false, "Dark" to true).forEach { (label, value) ->
                FilterChip(selected = settings.darkTheme == value, onClick = { ui.updateSettings { it.copy(darkTheme = value) } }, label = { Text(label) })
            }
        }
        OutlinedButton(onClick = { ui.password = ""; ui.passwordAction = "export" }, enabled = ui.backup.profiles.isNotEmpty()) { Text("Create encrypted local backup") }
        OutlinedButton(enabled = !status.running, onClick = onRestore) { Text("Restore encrypted local backup") }
        Text("Backups include private credentials and require your password. Keep the password separately; it cannot be recovered.")
        HorizontalDivider()
        Text("Components", style = MaterialTheme.typography.titleLarge)
        var versions by remember { mutableStateOf("") }
        LaunchedEffect(Unit) {
            versions = withContext(Dispatchers.IO) {
                runCatching { context.assets.open("native-versions.json").bufferedReader().use { it.readText() } }.getOrDefault("Native components are not packaged yet.")
            }
        }
        Text(versions, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
        Text("Android 16+ · ARM64 · SSLSocks Pro ${BuildConfig.VERSION_NAME}")
        var licenses by remember { mutableStateOf("") }
        LaunchedEffect(Unit) { licenses = withContext(Dispatchers.IO) { context.assets.open("THIRD_PARTY_NOTICES.txt").bufferedReader().use { it.readText() } } }
        Text(licenses, style = MaterialTheme.typography.bodySmall)
        Text("Network routing does not hide account identity, device permissions, or data you give to other apps.")
    }
}
