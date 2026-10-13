package io.github.cysin.sslsockspro.ui

import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.lifecycle.ViewModel
import io.github.cysin.sslsockspro.model.Backup
import io.github.cysin.sslsockspro.model.TunnelProfile

/** Drafts and pending document results survive activity rotation in memory.
 * Credentials are never placed in Android saved-state bundles. */
class TunnelUiState : ViewModel() {
    val backup = mutableStateOf(Backup(profiles = emptyList()))
    val loading = mutableStateOf(true)
    val page = mutableIntStateOf(0)
    val error = mutableStateOf<String?>(null)
    val editor = mutableStateOf<TunnelProfile?>(null)
    val pendingConnect = mutableStateOf<TunnelProfile?>(null)
    val pendingNotification = mutableStateOf<TunnelProfile?>(null)
    val passwordAction = mutableStateOf<String?>(null)
    val password = mutableStateOf("")
    val pendingRestore = mutableStateOf<ByteArray?>(null)
    val pendingExport = mutableStateOf<ByteArray?>(null)
    override fun onCleared() {
        pendingRestore.value?.fill(0)
        pendingExport.value?.fill(0)
        pendingRestore.value = null; pendingExport.value = null
        password.value = ""; editor.value = null
        pendingConnect.value = null; pendingNotification.value = null
    }
}
