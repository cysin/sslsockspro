package io.github.cysin.sslsockspro

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import io.github.cysin.sslsockspro.data.ProfileStore

class TunnelApplication : Application() {
    val profiles by lazy { ProfileStore(this) }
    override fun onCreate() {
        super.onCreate()
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel("tunnel", "Tunnel connection", NotificationManager.IMPORTANCE_LOW).apply {
                description = "Connection status and controls"; setShowBadge(false)
            }
        )
    }
}
