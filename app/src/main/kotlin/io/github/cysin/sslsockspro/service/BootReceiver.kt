package io.github.cysin.sslsockspro.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import io.github.cysin.sslsockspro.TunnelApplication
import io.github.cysin.sslsockspro.model.ConnectionMode

/** Opt-in: restart the selected local proxy after boot. VPN profiles use
 * Android's always-on VPN, which also protects traffic before the app runs. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        val pending = goAsync()
        Thread {
            try {
                val store = (context.applicationContext as TunnelApplication).profiles
                val settings = store.settings()
                val id = settings.selectedProfileId
                if (settings.bootStartLocalProxy && id != null && store.profile(id)?.mode == ConnectionMode.LOCAL_PROXY)
                    QuickControls.connectSelected(context)
            } catch (_: Exception) {
            } finally { pending.finish() }
        }.start()
    }
}
