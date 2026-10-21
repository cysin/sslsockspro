package io.github.cysin.sslsockspro.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import io.github.cysin.sslsockspro.config.Endpoint
import io.github.cysin.sslsockspro.config.StunnelDocument
import io.github.cysin.sslsockspro.data.Credentials
import io.github.cysin.sslsockspro.data.Gateways
import io.github.cysin.sslsockspro.data.OpenVpnDocument
import io.github.cysin.sslsockspro.model.ConnectionMode
import io.github.cysin.sslsockspro.model.DnsMode
import io.github.cysin.sslsockspro.model.ProxyKind
import io.github.cysin.sslsockspro.model.TunnelProfile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.Base64

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun ProfileEditor(profile: TunnelProfile, onChange: (TunnelProfile) -> Unit, onImport: () -> Unit,
                           onDismiss: () -> Unit, onSave: (TunnelProfile) -> Unit) {
    val scope = rememberCoroutineScope()
    val document = remember(profile.config) { runCatching { StunnelDocument.parse(profile.config) }.getOrNull() }
    val section = profile.selectedSection.takeIf { it in document?.sections.orEmpty() } ?: document?.sections?.firstOrNull().orEmpty()
    var advanced by remember(profile.id) { mutableStateOf(false) }
    var modeMenu by remember { mutableStateOf(false) }
    var proxyMenu by remember { mutableStateOf(false) }
    var sectionMenu by remember { mutableStateOf(false) }
    var validation by remember { mutableStateOf<String?>(null) }
    var appPicker by remember { mutableStateOf(false) }
    var unlockFile by remember { mutableStateOf<String?>(null) }
    var keyPassword by remember { mutableStateOf("") }
    var unlocking by remember { mutableStateOf(false) }
    fun save() {
        try {
            require(profile.name.isNotBlank()) { "Profile name is required" }
            if (profile.mode != ConnectionMode.OPENVPN || profile.openVpnViaStunnel) document?.validate() ?: error("Add a stunnel client configuration")
            if (profile.mode == ConnectionMode.OPENVPN) OpenVpnDocument.validate(profile.openVpnConfig)
            onSave(profile)
        } catch (failure: Exception) { validation = failure.message ?: "Configuration is incomplete" }
    }
    Dialog(onDismissRequest = onDismiss, properties = DialogProperties(usePlatformDefaultWidth = false)) {
        Surface(Modifier.fillMaxSize()) {
            Scaffold(topBar = { TopAppBar(title = { Text("Profile settings") }, navigationIcon = {
                IconButton(onClick = onDismiss) { Icon(Icons.Default.Close, "Cancel editing") }
            }, actions = { TextButton(onClick = ::save) { Text("Save") } }) }) { padding ->
                Column(Modifier.padding(padding).padding(horizontal = 20.dp).verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(14.dp)) {
                    Spacer(Modifier.height(4.dp))
                    SecureTextField(profile.name, { onChange(profile.copy(name = it)) }, "Profile name", Modifier.fillMaxWidth())
                    Box {
                        OutlinedButton(onClick = { modeMenu = true }) { Text(modeLabel(profile.mode)) }
                        DropdownMenu(modeMenu, { modeMenu = false }) { ConnectionMode.entries.forEach { mode ->
                            DropdownMenuItem(text = { Text(modeLabel(mode)) }, onClick = { onChange(profile.copy(mode = mode)); modeMenu = false })
                        } }
                    }
                    if (profile.mode == ConnectionMode.OPENVPN) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(profile.openVpnViaStunnel, { onChange(profile.copy(openVpnViaStunnel = it)) }); Text("Carry OpenVPN TCP through stunnel")
                        }
                        Text("Import an .ovpn file and its companion credentials. TAP, scripts, and compression are unsupported.")
                        SecureTextField(profile.openVpnConfig, { onChange(profile.copy(openVpnConfig = it)) }, "OpenVPN configuration",
                            Modifier.fillMaxWidth(), singleLine = false, monospace = true, lines = 8)
                        if (!profile.openVpnViaStunnel && Gateways.lookedUpNames(profile).isNotEmpty()) Text(LOOKUP_WARNING, color = MaterialTheme.colorScheme.error)
                        SecureTextField(profile.openVpnUsername, { onChange(profile.copy(openVpnUsername = it)) }, "Username, if required", Modifier.fillMaxWidth())
                        SecureTextField(profile.openVpnPassword, { onChange(profile.copy(openVpnPassword = it)) }, "Password, if required",
                            Modifier.fillMaxWidth(), secret = true)
                        SecureTextField(profile.openVpnKeyPassphrase, { onChange(profile.copy(openVpnKeyPassphrase = it)) },
                            "Private key / PKCS#12 passphrase, if required", Modifier.fillMaxWidth(), secret = true)
                    }
                    if (profile.mode != ConnectionMode.OPENVPN || profile.openVpnViaStunnel) {
                        if (profile.mode != ConnectionMode.LOCAL_PROXY) Box {
                            OutlinedButton(onClick = { proxyMenu = true }) { Text(if (profile.proxyKind == ProxyKind.HTTP_CONNECT) "HTTP CONNECT backend" else "SOCKS5 backend") }
                            DropdownMenu(proxyMenu, { proxyMenu = false }) { ProxyKind.entries.forEach { kind ->
                                DropdownMenuItem(text = { Text(if (kind == ProxyKind.HTTP_CONNECT) "HTTP CONNECT" else "SOCKS5") },
                                    onClick = { onChange(profile.copy(proxyKind = kind)); proxyMenu = false })
                            } }
                        }
                        if (profile.mode != ConnectionMode.LOCAL_PROXY) {
                            Text("The app checks the backend type when connecting and uses what the server answers.", style = MaterialTheme.typography.bodySmall)
                            SecureTextField(profile.proxyUsername, { onChange(profile.copy(proxyUsername = it)) }, "Backend proxy username, if required", Modifier.fillMaxWidth())
                            if (profile.proxyUsername.isNotEmpty()) SecureTextField(profile.proxyPassword, { onChange(profile.copy(proxyPassword = it)) },
                                "Backend proxy password", Modifier.fillMaxWidth(), secret = true)
                        }
                        if (document?.sections.orEmpty().size > 1) Box {
                            OutlinedButton(onClick = { sectionMenu = true }) { Text("Selected tunnel: $section") }
                            DropdownMenu(sectionMenu, { sectionMenu = false }) { document!!.sections.forEach { item ->
                                DropdownMenuItem(text = { Text(item) }, onClick = { onChange(profile.copy(selectedSection = item)); sectionMenu = false })
                            } }
                        }
                        if (document != null && section.isNotEmpty() && !advanced && document.values(section, "connect").size == 1) key(section) {
                            BasicTunnelFields(document, section, profile.mode) { config -> onChange(profile.copy(config = config)) }
                        }
                        if (!advanced && document?.values(section, "connect").orEmpty().size > 1)
                            Text("This tunnel has several failover destinations. Use the advanced editor to change them individually.")
                        TextButton(onClick = { advanced = !advanced }) { Text(if (advanced) "Show basic server settings" else "Edit advanced stunnel configuration") }
                        if (advanced) SecureTextField(profile.config, { onChange(profile.copy(config = it)) }, "stunnel client configuration",
                            Modifier.fillMaxWidth(), singleLine = false, monospace = true, lines = 10)
                        Text("TLS 1.3, server certificate verification, and a client identity are required. Repeated socket options and additional tunnels are preserved.")
                    }
                    HorizontalDivider()
                    Text("Private credentials", style = MaterialTheme.typography.titleLarge)
                    Text("Import CA certificates, a client certificate/key, or OpenVPN companion files. Files are encrypted in private app storage.")
                    OutlinedButton(onClick = onImport) { Text("Attach files or an OpenVPN profile") }
                    val references = (document?.credentialReferences().orEmpty() +
                        runCatching { OpenVpnDocument.credentialReferences(profile.openVpnConfig) }.getOrDefault(emptyList()))
                        .map(Credentials::referenceName).distinct()
                    for (reference in references) {
                        var menu by remember(reference) { mutableStateOf(false) }
                        Box {
                            TextButton(onClick = { menu = true }) { Text("$reference: " + if (reference in profile.files) "attached" else "missing — select a file") }
                            DropdownMenu(menu, { menu = false }) { profile.files.keys.forEach { name ->
                                DropdownMenuItem(text = { Text(name) }, onClick = { onChange(profile.copy(files = profile.files + (reference to profile.files.getValue(name)))); menu = false })
                            } }
                        }
                    }
                    profile.files.keys.forEach { name ->
                        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                            Text(name, Modifier.weight(1f))
                            if (name.endsWith(".pem", true) || name.endsWith(".key", true))
                                TextButton(onClick = { unlockFile = name; keyPassword = "" }) { Text("Unlock key") }
                            TextButton(onClick = { onChange(profile.copy(files = profile.files - name)) }) { Text("Remove") }
                        }
                    }
                    if (profile.mode != ConnectionMode.LOCAL_PROXY) {
                        HorizontalDivider()
                        Text("VPN coverage", style = MaterialTheme.typography.titleLarge)
                        Text(if (profile.includedApps.isEmpty()) "All apps are routed through the VPN." else profile.includedApps.size.toString() + " selected apps are routed. Other apps use their normal connection.")
                        OutlinedButton(onClick = { appPicker = true }) { Text("Select apps") }
                    }
                    if (profile.mode == ConnectionMode.PROXY_VPN) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(profile.dnsMode == DnsMode.PROXY, { onChange(profile.copy(dnsMode = if (it) DnsMode.PROXY else DnsMode.DOH)) })
                            Text("Resolve names at the proxy server")
                        }
                        Text(if (profile.dnsMode == DnsMode.PROXY) "Apps receive placeholder addresses and your proxy looks names up, so no DNS-over-HTTPS provider sees them. " +
                            "Other record types, such as mail or service records, still use DNS-over-HTTPS through the tunnel."
                            else "Apps' lookups use DNS-over-HTTPS through the tunnel; the provider below sees the names and your proxy's address.",
                            style = MaterialTheme.typography.bodySmall)
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(profile.proxyIpv6, { onChange(profile.copy(proxyIpv6 = it)) }); Text("Enable IPv6 destinations")
                        }
                        Text("Enable only when the proxy exit can reach IPv6 sites. When disabled, Android blocks IPv6 and apps use IPv4; there is no direct IPv6 fallback.")
                        SecureTextField(profile.dnsEndpoint, { onChange(profile.copy(dnsEndpoint = it)) }, "DNS-over-HTTPS endpoint", Modifier.fillMaxWidth(),
                            error = if (Regex("https://[^\\s/@]+(:\\d+)?(/\\S*)?").matches(profile.dnsEndpoint)) null else "Use an https:// address without credentials")
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(profile.suppressServiceBindings, { onChange(profile.copy(suppressServiceBindings = it)) }); Text("Suppress DNS SVCB/HTTPS (64/65)")
                        }
                        Text("DNS uses HTTPS through this tunnel. Other UDP, including QUIC, is blocked. Set Android Private DNS to Automatic or Off.")
                    }
                    validation?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                    Button(onClick = ::save, modifier = Modifier.fillMaxWidth()) { Text("Save profile") }
                    Spacer(Modifier.height(24.dp))
                }
            }
        }
    }
    if (appPicker) AppPicker(profile.includedApps, { onChange(profile.copy(includedApps = it)) }, { appPicker = false })
    unlockFile?.let { name ->
        AlertDialog(onDismissRequest = { if (!unlocking) { unlockFile = null; keyPassword = "" } }, title = { Text("Unlock $name") },
            text = { Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("The unlocked key will stay encrypted in private app storage. No key is exported.")
                SecureTextField(keyPassword, { keyPassword = it }, "Private key passphrase", Modifier.fillMaxWidth(), secret = true)
            } }, confirmButton = { TextButton(enabled = !unlocking, onClick = {
                unlocking = true
                val password = keyPassword.toCharArray(); keyPassword = ""
                scope.launch {
                    try {
                        val normalized = withContext(Dispatchers.IO) { Credentials.normalizeIdentity(Credentials.bytes(profile, name), password) }
                        onChange(profile.copy(files = profile.files + (name to Base64.getEncoder().encodeToString(normalized))))
                        normalized.fill(0); unlockFile = null
                    } catch (_: Exception) { validation = "Could not unlock the key. Check its file and passphrase." }
                    finally { password.fill('\u0000'); unlocking = false }
                }
            }) { Text(if (unlocking) "Unlocking…" else "Unlock") } },
            dismissButton = { TextButton(enabled = !unlocking, onClick = { unlockFile = null; keyPassword = "" }) { Text("Cancel") } })
    }
}

private const val LOOKUP_WARNING = "The server name is looked up on your current network before each connection, which reveals it to that network. " +
    "Use an IP address to avoid the lookup; the certificate name still verifies the server."

@Composable
private fun BasicTunnelFields(document: StunnelDocument, section: String, mode: ConnectionMode, onChange: (String) -> Unit) {
    val scope = rememberCoroutineScope()
    val remote = runCatching { document.remotes(section).first() }.getOrDefault(Endpoint("SERVER_IP", 9983))
    val listener = runCatching { document.listener(section) }.getOrDefault(Endpoint("127.0.0.1", 33009))
    var host by remember { mutableStateOf(remote.host) }
    var port by remember { mutableStateOf(remote.port.toString()) }
    var localPort by remember { mutableStateOf(listener.port.toString()) }
    var identity by remember { mutableStateOf(document.effective(section, "checkhost") ?: document.effective(section, "checkip").orEmpty()) }
    var lookup by remember { mutableStateOf<String?>(null) }
    val identityOption = if (!document.effective(section, "checkhost").isNullOrBlank()) "checkHost" else "checkIP"
    fun endpoint() = if (host.contains(':')) "[$host]:$port" else "$host:$port"
    SecureTextField(host, { host = it; onChange(document.updated(section, "connect", endpoint())) }, "Server IP or hostname", Modifier.fillMaxWidth())
    if (host.isNotBlank() && !Gateways.isAddressLiteral(host)) {
        Text(LOOKUP_WARNING, color = MaterialTheme.colorScheme.error)
        TextButton(onClick = {
            val name = host
            scope.launch {
                // An explicit user action; during a VPN session this lookup is tunneled.
                lookup = try {
                    host = withContext(Dispatchers.IO) { java.net.InetAddress.getAllByName(name).first().hostAddress!! }
                    onChange(document.updated(section, "connect", endpoint()))
                    null
                } catch (_: Exception) { "Could not look up $name" }
            }
        }) { Text("Use its current IP address") }
        lookup?.let { Text(it, color = MaterialTheme.colorScheme.error) }
    }
    Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        SecureTextField(port, { port = it; onChange(document.updated(section, "connect", endpoint())) }, "Server port", Modifier.weight(1f), number = true,
            error = if (port.toIntOrNull() in 1..65535) null else "Use 1–65535")
        SecureTextField(localPort, { localPort = it; onChange(document.updated(section, "accept",
            if (listener.host.contains(':')) "[" + listener.host + "]:" + it else listener.host + ":" + it)) },
            "Local port", Modifier.weight(1f), number = true, error = if (localPort.toIntOrNull() in 1024..65535) null else "Use 1024–65535")
    }
    if (mode != ConnectionMode.LOCAL_PROXY) Text("VPN modes reach this tunnel through a private per-connection endpoint that only this app can use; the local port applies to Local proxy mode.",
        style = MaterialTheme.typography.bodySmall)
    SecureTextField(identity, { identity = it; onChange(document.updated(section, identityOption, it)) },
        if (identityOption == "checkHost") "Server certificate name" else "Server certificate IP", Modifier.fillMaxWidth(),
        supportingText = "Must match the server certificate. It can differ from the connection IP.")
}
