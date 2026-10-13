package io.github.cysin.sslsockspro

import android.content.Intent
import android.net.VpnService
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.cysin.sslsockspro.data.PackageImporter
import io.github.cysin.sslsockspro.model.ConnectionMode
import io.github.cysin.sslsockspro.model.ConnectionStage
import io.github.cysin.sslsockspro.service.ConnectionService
import io.github.cysin.sslsockspro.service.TunnelState
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket

@RunWith(AndroidJUnit4::class)
class OpenVpnDeviceTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private val store get() = (context.applicationContext as TunnelApplication).profiles

    private fun await(timeout: Long = 30000, condition: () -> Boolean) {
        val end = System.nanoTime() + timeout * 1000000
        while (System.nanoTime() < end) { if (condition()) return; Thread.sleep(100) }
        fail("OpenVPN test timed out: " + TunnelState.status.value + "\n" + TunnelState.logs.value.takeLast(30).joinToString("\n"))
    }

    @Test fun authenticatedOpenVpnDataChannelsAndAddressFamilyPolicy() {
        val name = InstrumentationRegistry.getArguments().getString("openVpnFixture")
        assumeTrue("Provide the disposable --openvpn-fixture", name != null)
        val old = store.read()
        try {
            val bytes = readTestFixture(name!!)
            val imported = PackageImporter.profiles(PackageImporter.entries(bytes, "fixture.zip")).single()
            bytes.fill(0)
            val profile = imported.copy(name = "Disposable OpenVPN test", mode = ConnectionMode.OPENVPN, includedApps = listOf(context.packageName))
            val activity = instrumentation.startActivitySync(Intent(context, io.github.cysin.sslsockspro.ui.MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            instrumentation.runOnMainSync { activity.window.addFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON) }
            VpnService.prepare(context)?.let { permission ->
                instrumentation.runOnMainSync { activity.startActivityForResult(permission, 9002) }
                await(60000) { VpnService.prepare(context) == null }
            }
            store.settings(old.settings.copy(reconnect = false))
            for (throughStunnel in listOf(false, true)) {
                val selected = profile.copy(openVpnViaStunnel = throughStunnel)
                store.save(selected)
                instrumentation.runOnMainSync { ConnectionService.start(context, selected) }
                await { TunnelState.status.value.stage == ConnectionStage.CONNECTED }
                assertTrue(TunnelState.status.value.vpnActive)
                val previous = TunnelState.status.value.bytesSent
                DatagramSocket().use { socket ->
                    for (address in listOf("198.51.100.10", "2001:db8::10")) {
                        val payload = ByteArray(128) { 0x42 }
                        socket.send(DatagramPacket(payload, payload.size, InetAddress.getByName(address), 9999))
                    }
                }
                await(10000) { TunnelState.status.value.bytesSent >= previous + 256 }
                instrumentation.runOnMainSync { ConnectionService.stop(context) }
                await(10000) { !TunnelState.status.value.running }
                Thread.sleep(500)
            }

            val ipv6Only = profile.copy(openVpnViaStunnel = false, openVpnConfig = profile.openVpnConfig
                .replace("ifconfig 10.8.0.2 10.8.0.1\n", "")
                .replace("dhcp-option DNS 10.8.0.1", "dhcp-option DNS fd00:8::1"))
            store.save(ipv6Only)
            instrumentation.runOnMainSync { ConnectionService.start(context, ipv6Only) }
            await { TunnelState.status.value.stage == ConnectionStage.CONNECTED }
            val previous = TunnelState.status.value.bytesSent
            DatagramSocket().use { socket ->
                val payload = ByteArray(128) { 0x42 }
                socket.send(DatagramPacket(payload, payload.size, InetAddress.getByName("2001:db8::10"), 9999))
            }
            await(10000) { TunnelState.status.value.bytesSent >= previous + 128 }
            assertThrows(java.io.IOException::class.java) {
                Socket().use { it.connect(InetSocketAddress("198.51.100.10", 443), 1000) }
            }
            instrumentation.runOnMainSync { ConnectionService.stop(context) }
            await(10000) { !TunnelState.status.value.running }
            Thread.sleep(500)

            // Missing tunneled DNS is a permanent configuration error. Keep
            // the initial blocking interface instead of inheriting host DNS.
            val noDns = profile.copy(openVpnViaStunnel = false,
                openVpnConfig = profile.openVpnConfig.replace("dhcp-option DNS 10.8.0.1\n", ""))
            store.settings(store.read().settings.copy(reconnect = true))
            store.save(noDns)
            instrumentation.runOnMainSync { ConnectionService.start(context, noDns) }
            await { TunnelState.status.value.stage == ConnectionStage.ERROR &&
                TunnelState.status.value.message.contains("DNS server") }
            assertTrue(TunnelState.status.value.vpnActive)
            Thread.sleep(2000)
            assertEquals(ConnectionStage.ERROR, TunnelState.status.value.stage)
            assertTrue(TunnelState.status.value.message.contains("DNS server"))
            instrumentation.runOnMainSync { ConnectionService.stop(context) }
            await(10000) { !TunnelState.status.value.running }
        } finally {
            if (TunnelState.status.value.running) {
                instrumentation.runOnMainSync { ConnectionService.stop(context) }
                runCatching { await(10000) { !TunnelState.status.value.running } }
            }
            store.write(old)
        }
    }
}
