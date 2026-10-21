package io.github.cysin.sslsockspro.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import io.github.cysin.sslsockspro.model.TunnelProfile

@Composable
internal fun ProfilesScreen(ui: MainViewModel, padding: PaddingValues, onDelete: (TunnelProfile) -> Unit) {
    val status by rememberConnectionActivity()
    LazyColumn(Modifier.padding(padding).padding(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(12.dp),
        contentPadding = PaddingValues(bottom = 100.dp, top = 12.dp)) {
        if (ui.backup.profiles.isEmpty()) item { Text("No profiles yet. Import your stunnel client package or create a profile.") }
        items(ui.backup.profiles, key = { it.id }) { profile ->
            // Active profiles are immutable until disconnected.
            val editable = status.profileId != profile.id || !status.running
            ElevatedCard(Modifier.fillMaxWidth()) { Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(profile.name, style = MaterialTheme.typography.titleLarge)
                Text(modeLabel(profile.mode))
                Text(if (profile.operatorKeyFingerprint.isNotEmpty()) "Signed package · operator ${profile.operatorKeyFingerprint.take(16).chunked(4).joinToString(" ")}"
                    else "Unsigned or manually created profile", style = MaterialTheme.typography.bodySmall)
                ui.tunnels[profile.id].orEmpty().forEach { Text(it, maxLines = 2, overflow = TextOverflow.Ellipsis) }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    TextButton(onClick = { ui.select(profile.id) { ui.page = 0 } }) { Text("Select") }
                    TextButton(enabled = editable, onClick = { ui.editor = profile }) { Text("Edit") }
                    TextButton(enabled = editable, onClick = { onDelete(profile) }) { Text("Delete") }
                }
            } }
        }
    }
}
