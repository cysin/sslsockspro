package io.github.cysin.sslsockspro.ui

import android.content.Intent
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.provider.Settings
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.cysin.sslsockspro.data.Gateways
import io.github.cysin.sslsockspro.model.ConnectionMode
import io.github.cysin.sslsockspro.model.ConnectionStage
import io.github.cysin.sslsockspro.model.TunnelProfile
import io.github.cysin.sslsockspro.service.ConnectionService
import io.github.cysin.sslsockspro.service.TunnelState

@Composable
internal fun StatusScreen(ui: MainViewModel, padding: PaddingValues, onConnect: (TunnelProfile) -> Unit, onImport: () -> Unit) {
    val context = LocalContext.current
    val status by rememberConnectionActivity()
    val backup = ui.backup
    val selected = ui.selected
    val active = status.running
    val displayedProfile = backup.profiles.firstOrNull { active && it.id == status.profileId } ?: selected
    val network = rememberPhysicalNetworkWarnings()
    Column(Modifier.padding(padding).padding(20.dp).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(18.dp)) {
        Text("Your connection", style = MaterialTheme.typography.headlineMedium)
        ElevatedCard(Modifier.fillMaxWidth()) { Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(if (status.stage == ConnectionStage.CONNECTED) Icons.Default.VerifiedUser else Icons.Default.Shield, null)
                Spacer(Modifier.width(12.dp))
                Text(stageLabel(status.stage), style = MaterialTheme.typography.titleLarge)
            }
            Text(status.message)
            if (displayedProfile?.mode == ConnectionMode.PROXY_VPN) Text(
                if (displayedProfile.proxyIpv6) "IPv4 and IPv6 destinations enabled" else "IPv4 destinations; IPv6 blocked")
            if (displayedProfile != null) {
                Text(displayedProfile.name, style = MaterialTheme.typography.titleMedium)
                Text(modeLabel(displayedProfile.mode), style = MaterialTheme.typography.bodyMedium)
                if (!active && backup.profiles.size > 1) ProfileSelector(backup.profiles) { id -> ui.select(id) }
            } else Text("Import a client package with its certificates to get started.")
            Button(onClick = { if (active) ConnectionService.stop(context) else selected?.let(onConnect) },
                enabled = !status.alwaysOn && status.stage != ConnectionStage.STOPPING && (active || selected != null),
                modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp)) {
                Text(if (status.alwaysOn) "Controlled by Android always-on VPN" else if (status.stage == ConnectionStage.STOPPING) "Disconnecting…"
                    else if (active) "Disconnect" else "Connect")
            }
            if (selected == null) OutlinedButton(onClick = onImport, modifier = Modifier.fillMaxWidth()) { Text("Import client package") }
        } }
        if (displayedProfile != null) {
            Text(when (displayedProfile.mode) {
                ConnectionMode.LOCAL_PROXY -> "Local proxy mode covers apps configured to use the listener. It does not route the whole phone."
                ConnectionMode.PROXY_VPN -> "TCP and encrypted DNS use your server. Other UDP, including QUIC, is blocked. No direct fallback."
                ConnectionMode.OPENVPN -> "An OpenVPN server and a valid .ovpn profile are required. Your stunnel proxy can carry the OpenVPN TCP connection."
            })
            if (Gateways.lookedUpNames(displayedProfile).isNotEmpty()) Text(
                "This profile's server name is looked up on your current network before connecting. Use an IP address in the profile to avoid revealing it.",
                style = MaterialTheme.typography.bodySmall)
            if (displayedProfile.includedApps.isNotEmpty()) Text("Coverage: ${displayedProfile.includedApps.size} selected " +
                (if (displayedProfile.includedApps.size == 1) "app." else "apps.") + " Android block-without-VPN settings may block other apps.")
            ui.certificates[displayedProfile.id].orEmpty().filter { it.clientIdentity }.minByOrNull { it.expires }?.let { certificate ->
                val days = (certificate.expires - System.currentTimeMillis()) / 86_400_000
                if (days < 30) Text("Client certificate expires ${date(certificate.expires)}. Import its replacement before expiry.", color = MaterialTheme.colorScheme.error)
            }
            TrafficCounters()
        }
        if (network.captivePortal) {
            Text("This hotspot requires sign-in. Finish sign-in before connecting; the app will not bypass a blocked VPN.", color = MaterialTheme.colorScheme.error)
            OutlinedButton(onClick = { context.startActivity(Intent(Settings.ACTION_WIFI_SETTINGS)) }) { Text("Open Wi-Fi sign-in settings") }
        }
        if (network.strictPrivateDns && selected?.mode == ConnectionMode.PROXY_VPN) Text(
            "Set Android Private DNS to Automatic or Off. This VPN supplies DNS-over-HTTPS through your tunnel and never falls back to direct DNS.",
            color = MaterialTheme.colorScheme.error)
        OutlinedButton(onClick = { context.startActivity(Intent(Settings.ACTION_VPN_SETTINGS)) }) { Text("Always-on and block-without-VPN settings") }
        OutlinedButton(onClick = { context.startActivity(Intent(Settings.ACTION_WIFI_SETTINGS)) }) { Text("Wi-Fi and hotspot sign-in") }
    }
}

/** The only status reader that follows traffic counters. */
@Composable
private fun TrafficCounters() {
    val status by TunnelState.status.collectAsStateWithLifecycle()
    Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
        Text("Sent ${bytes(status.bytesSent)}")
        Text("Received ${bytes(status.bytesReceived)}")
    }
}

private data class NetworkWarnings(val captivePortal: Boolean = false, val strictPrivateDns: Boolean = false)

/** Reads capabilities only; no SSID or location data is requested. */
@Composable
private fun rememberPhysicalNetworkWarnings(): NetworkWarnings {
    val context = LocalContext.current
    val manager = remember { context.getSystemService(ConnectivityManager::class.java) }
    var warnings by remember { mutableStateOf(NetworkWarnings()) }
    DisposableEffect(manager) {
        fun update() {
            val networks = manager.allNetworks.filter { network ->
                manager.getNetworkCapabilities(network)?.let { !it.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                    it.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) } == true
            }
            warnings = NetworkWarnings(
                captivePortal = networks.any { manager.getNetworkCapabilities(it)?.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL) == true },
                strictPrivateDns = networks.any { !manager.getLinkProperties(it)?.privateDnsServerName.isNullOrBlank() })
        }
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) { update() }
            override fun onLost(network: Network) { update() }
            override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) { update() }
            override fun onLinkPropertiesChanged(network: Network, properties: LinkProperties) { update() }
        }
        update()
        manager.registerNetworkCallback(NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(), callback)
        onDispose { manager.unregisterNetworkCallback(callback) }
    }
    return warnings
}

@Composable
private fun ProfileSelector(profiles: List<TunnelProfile>, onSelect: (String) -> Unit) {
    var expanded by remember { mutableStateOf(false) }
    Box {
        OutlinedButton(onClick = { expanded = true }) { Text("Choose profile") }
        DropdownMenu(expanded, onDismissRequest = { expanded = false }) {
            profiles.forEach { profile -> DropdownMenuItem(text = { Text(profile.name) }, onClick = { onSelect(profile.id); expanded = false }) }
        }
    }
}
