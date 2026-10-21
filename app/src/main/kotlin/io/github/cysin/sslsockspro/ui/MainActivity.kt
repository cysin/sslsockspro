package io.github.cysin.sslsockspro.ui

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import io.github.cysin.sslsockspro.service.TunnelState

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Profiles, keys, logs and addresses must not appear in screenshots,
        // screen recordings, casting, or the recent-apps thumbnail. Compose
        // dialogs and menus inherit this flag from the activity window.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        setRecentsScreenshotEnabled(false)
        enableEdgeToEdge()
        setContent { TunnelApp() }
    }

    override fun onStart() { super.onStart(); TunnelState.uiVisible(true) }
    override fun onStop() { TunnelState.uiVisible(false); super.onStop() }
}
