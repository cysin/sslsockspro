package io.github.cysin.sslsockspro.ui

import androidx.compose.runtime.Composable
import androidx.compose.runtime.State
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.cysin.sslsockspro.model.ConnectionMode
import io.github.cysin.sslsockspro.model.ConnectionStage
import io.github.cysin.sslsockspro.model.ConnectionStatus
import io.github.cysin.sslsockspro.service.TunnelState
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

/** Connection status without traffic counters, so counter updates do not
 * recompose screens that only depend on the connection stage. */
@Composable
internal fun rememberConnectionActivity(): State<ConnectionStatus> = TunnelState.activity.collectAsStateWithLifecycle()

internal fun modeLabel(mode: ConnectionMode) = when (mode) {
    ConnectionMode.LOCAL_PROXY -> "Local proxy"
    ConnectionMode.PROXY_VPN -> "Phone VPN through stunnel"
    ConnectionMode.OPENVPN -> "Built-in OpenVPN"
}

internal fun stageLabel(stage: ConnectionStage) = when (stage) {
    ConnectionStage.IDLE -> "Disconnected"; ConnectionStage.VALIDATING -> "Validating"; ConnectionStage.CONNECTING -> "Connecting"
    ConnectionStage.LISTENING -> "Local proxy ready"; ConnectionStage.CONNECTED -> "Connected"; ConnectionStage.RECONNECTING -> "Reconnecting"
    ConnectionStage.STOPPING -> "Stopping"; ConnectionStage.ERROR -> "Needs attention"
}

internal fun date(milliseconds: Long): String =
    DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm z").format(Instant.ofEpochMilli(milliseconds).atZone(ZoneId.systemDefault()))

internal fun bytes(value: Long): String = when {
    value >= 1024 * 1024 -> "%.1f MiB".format(value / 1048576.0)
    value >= 1024 -> "%.1f KiB".format(value / 1024.0)
    else -> "$value B"
}
