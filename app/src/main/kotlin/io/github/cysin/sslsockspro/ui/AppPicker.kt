package io.github.cysin.sslsockspro.ui

import android.content.Intent
import android.content.pm.PackageManager
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.graphics.drawable.toBitmap
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.Locale

private class AppEntry(val packageName: String, val label: String, val icon: ImageBitmap?)

/** Chooses the apps routed through the VPN. Apps load off the main thread.
 * Without QUERY_ALL_PACKAGES only apps with a launcher icon are visible to
 * this app, and Android can route only packages this app can see. */
@Composable
internal fun AppPicker(selected: List<String>, onChange: (List<String>) -> Unit, onDismiss: () -> Unit) {
    val context = LocalContext.current
    val apps by produceState<List<AppEntry>?>(null) {
        value = withContext(Dispatchers.IO) {
            val manager = context.packageManager
            manager.queryIntentActivities(Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER), PackageManager.ResolveInfoFlags.of(0))
                .distinctBy { it.activityInfo.packageName }
                .filter { it.activityInfo.packageName != context.packageName }
                .map { info ->
                    val icon = runCatching { info.loadIcon(manager).toBitmap(96, 96).asImageBitmap() }.getOrNull()
                    AppEntry(info.activityInfo.packageName, info.loadLabel(manager).toString(), icon)
                }
        }
    }
    var query by remember { mutableStateOf("") }
    var manual by remember { mutableStateOf("") }
    var manualError by remember { mutableStateOf<String?>(null) }
    val chosen = selected.toSet()
    AlertDialog(onDismissRequest = onDismiss, title = { Text("Choose VPN coverage") }, text = {
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            TextButton(onClick = { onChange(emptyList()); onDismiss() }) { Text("Route all apps") }
            SecureTextField(query, { query = it }, "Search apps", Modifier.fillMaxWidth())
            val list = apps
            if (list == null) Box(Modifier.fillMaxWidth().padding(16.dp), contentAlignment = Alignment.Center) { CircularProgressIndicator() }
            else {
                val known = list.map { it.packageName }.toSet()
                val needle = query.trim().lowercase(Locale.ROOT)
                val choices = (list + chosen.filterNot { it in known }.map { AppEntry(it, it, null) })
                    .filter { needle.isEmpty() || it.label.lowercase(Locale.ROOT).contains(needle) || it.packageName.contains(needle) }
                    .sortedWith(compareByDescending<AppEntry> { it.packageName in chosen }.thenBy { it.label.lowercase(Locale.ROOT) }.thenBy { it.packageName })
                LazyColumn(Modifier.heightIn(max = 380.dp)) {
                    items(choices, key = { it.packageName }) { app ->
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(app.packageName in chosen, { enabled ->
                                onChange(if (enabled) (selected + app.packageName).distinct() else selected - app.packageName)
                            })
                            app.icon?.let { Image(it, null, Modifier.size(32.dp)) } ?: Spacer(Modifier.size(32.dp))
                            Spacer(Modifier.width(8.dp))
                            Column { Text(app.label); Text(app.packageName, style = MaterialTheme.typography.bodySmall) }
                        }
                    }
                }
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                SecureTextField(manual, { manual = it; manualError = null }, "Add by package name", Modifier.weight(1f))
                TextButton(onClick = {
                    val name = manual.trim()
                    manualError = when {
                        !Regex("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z0-9_]+)+").matches(name) -> "Enter a package name such as org.example.app"
                        name == context.packageName -> "This app is always covered when it needs to be."
                        runCatching { context.packageManager.getApplicationInfo(name, PackageManager.ApplicationInfoFlags.of(0)) }.isFailure ->
                            "Android does not let this app see that package, so it cannot be routed. Apps with a launcher icon are listed above."
                        else -> null
                    }
                    if (manualError == null) { onChange((selected + name).distinct()); manual = "" }
                }) { Text("Add") }
            }
            manualError?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
        }
    }, confirmButton = { TextButton(onClick = onDismiss) { Text("Done") } })
}
