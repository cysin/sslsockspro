package io.github.cysin.sslsockspro.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp

@Composable
internal fun CertificatesScreen(ui: MainViewModel, padding: PaddingValues) {
    val status by rememberConnectionActivity()
    val selected = ui.selected
    LazyColumn(Modifier.padding(padding).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item { Text("Certificates stay in encrypted private app storage. Private keys are never displayed here.") }
        items(ui.backup.profiles.flatMap { profile -> ui.certificates[profile.id].orEmpty().map { profile.name to it } }) { (name, certificate) ->
            OutlinedCard(Modifier.fillMaxWidth()) { Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(name, style = MaterialTheme.typography.titleMedium)
                Text(certificate.name)
                Text(certificate.subject)
                Text("Expires ${date(certificate.expires)}",
                    color = if (certificate.expires < System.currentTimeMillis()) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface)
                Text("SHA-256 ${certificate.fingerprint}", style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
            } }
        }
        item {
            OutlinedButton(enabled = !status.running || selected?.id != status.profileId, onClick = { selected?.let { ui.editor = it } }) {
                Text("Manage files in selected profile")
            }
        }
    }
}
