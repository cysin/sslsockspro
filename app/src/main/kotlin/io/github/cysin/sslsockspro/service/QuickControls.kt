package io.github.cysin.sslsockspro.service

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.net.VpnService
import io.github.cysin.sslsockspro.TunnelApplication
import io.github.cysin.sslsockspro.model.ConnectionMode

/** Connect and disconnect from the tile, shortcuts and boot, outside the
 * app's screens. Consent dialogs need the app, so they are never skipped. */
object QuickControls {
    /** Starts the selected profile; false when the app must ask for consent. */
    fun connectSelected(context: Context): Boolean {
        val store = (context.applicationContext as TunnelApplication).profiles
        val id = store.settings().selectedProfileId ?: return false
        val profile = store.profile(id) ?: return false
        val notifications = context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED
        if (!notifications || (profile.mode != ConnectionMode.LOCAL_PROXY && VpnService.prepare(context) != null)) return false
        ConnectionService.start(context, profile)
        return true
    }

    fun disconnect(context: Context) {
        if (TunnelState.status.value.running && !TunnelState.status.value.alwaysOn) ConnectionService.stop(context)
    }
}
