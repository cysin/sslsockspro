package io.github.cysin.sslsockspro.ui

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import io.github.cysin.sslsockspro.service.QuickControls

/** Launcher shortcuts. Not exported: only the launcher, acting for this app,
 * can start it, so no other app can disconnect the tunnel through it. */
class ShortcutActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        when (intent?.action) {
            CONNECT -> if (!runCatching { QuickControls.connectSelected(this) }.getOrDefault(false))
                startActivity(Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            DISCONNECT -> QuickControls.disconnect(this)
        }
        finish()
    }

    companion object {
        const val CONNECT = "io.github.cysin.sslsockspro.CONNECT"
        const val DISCONNECT = "io.github.cysin.sslsockspro.DISCONNECT"
    }
}
