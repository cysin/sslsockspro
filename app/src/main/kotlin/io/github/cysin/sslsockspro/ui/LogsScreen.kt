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
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.cysin.sslsockspro.service.TunnelState

@Composable
internal fun LogsScreen(padding: PaddingValues, onExport: () -> Unit) {
    val logs by TunnelState.logs.collectAsStateWithLifecycle()
    Column(Modifier.padding(padding).padding(16.dp)) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text("Connection log", style = MaterialTheme.typography.titleLarge)
            TextButton(onClick = TunnelState::clearLogs) { Text("Clear") }
        }
        Text("Bounded diagnostics; no traffic payloads or automatic uploads.", style = MaterialTheme.typography.bodySmall)
        TextButton(onClick = onExport) { Text("Save redacted diagnostics") }
        LazyColumn(Modifier.weight(1f)) {
            items(logs) { Text(it, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(vertical = 4.dp)) }
        }
    }
}
