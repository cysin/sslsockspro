package io.github.cysin.sslsockspro.service

import io.github.cysin.sslsockspro.model.ConnectionStatus
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.time.Instant

object TunnelState {
    private val statusMutable = MutableStateFlow(ConnectionStatus())
    val status = statusMutable.asStateFlow()
    private val activityMutable = MutableStateFlow(ConnectionStatus())
    /** [status] without traffic counters; it changes only with the connection
     * itself, so screens that ignore counters are not recomposed by them. */
    val activity = activityMutable.asStateFlow()
    private val logsMutable = MutableStateFlow<List<String>>(emptyList())
    val logs = logsMutable.asStateFlow()
    @Synchronized fun status(value: ConnectionStatus) {
        statusMutable.value = value
        activityMutable.value = value.copy(bytesSent = 0, bytesReceived = 0)
    }
    @Synchronized fun log(message: String) {
        if (message.contains(Regex("(?i)password|passphrase|authorization|private.?key|bearer\\s|auth.?token|session.?token|cookie"))) {
            logsMutable.value = logsMutable.value.takeLast(499) + "${Instant.now()} [credential-related diagnostic redacted]"
            return
        }
        val redacted = message
            .replace(Regex("/(?:data|home)/[^\\s]+"), "[private path]").take(1024)
        logsMutable.value = (logsMutable.value.takeLast(499) + "${Instant.now()} $redacted")
    }
    @Synchronized fun clearLogs() { logsMutable.value = emptyList() }
}
