package io.github.cysin.sslsockspro.ui

import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import io.github.cysin.sslsockspro.service.TunnelState
import kotlinx.coroutines.flow.MutableStateFlow

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Profiles, keys, logs and addresses must not appear in screenshots,
        // screen recordings, casting, or the recent-apps thumbnail. Compose
        // dialogs and menus inherit this flag from the activity window.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        setRecentsScreenshotEnabled(false)
        enableEdgeToEdge()
        // A recreated activity has already handled its launch intent.
        if (savedInstanceState == null) incoming.value = intent
        setContent { TunnelApp(incoming) }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        incoming.value = intent
    }

    /** Files opened or shared from other apps, handled once by [TunnelApp]. */
    private val incoming = MutableStateFlow<Intent?>(null)

    override fun onStart() { super.onStart(); TunnelState.uiVisible(true) }
    override fun onStop() { TunnelState.uiVisible(false); super.onStop() }
}
