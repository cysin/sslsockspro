package io.github.cysin.sslsockspro.service

import android.app.PendingIntent
import android.content.Intent
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import io.github.cysin.sslsockspro.model.ConnectionStage
import io.github.cysin.sslsockspro.ui.MainActivity

/** Quick Settings toggle. It shows only the connection state, never a
 * profile or server name, and requires unlocking before it acts. */
class TunnelTileService : TileService() {
    override fun onStartListening() = update()

    override fun onClick() {
        unlockAndRun {
            val status = TunnelState.status.value
            if (status.running) QuickControls.disconnect(this)
            else if (!runCatching { QuickControls.connectSelected(this) }.getOrDefault(false)) {
                val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                    PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
                startActivityAndCollapse(open)
            }
            update()
        }
    }

    private fun update() {
        val status = TunnelState.status.value
        qsTile?.apply {
            state = if (status.running) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
            subtitle = when (status.stage) {
                ConnectionStage.CONNECTED -> "Connected"
                ConnectionStage.LISTENING -> "Local proxy ready"
                ConnectionStage.IDLE -> "Off"
                ConnectionStage.ERROR -> "Needs attention"
                else -> "Working…"
            }
            updateTile()
        }
    }
}
