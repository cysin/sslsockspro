package io.github.cysin.sslsockspro

import android.app.ActivityManager
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Process
import android.view.accessibility.AccessibilityNodeInfo
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.cysin.sslsockspro.config.StunnelDocument
import io.github.cysin.sslsockspro.data.Credentials
import io.github.cysin.sslsockspro.data.PackageImporter
import io.github.cysin.sslsockspro.model.ConnectionMode
import io.github.cysin.sslsockspro.model.ConnectionStage
import io.github.cysin.sslsockspro.network.TunneledDns
import io.github.cysin.sslsockspro.service.ConnectionService
import io.github.cysin.sslsockspro.service.TunnelState
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.xbill.DNS.DClass
import org.xbill.DNS.Message
import org.xbill.DNS.Name
import org.xbill.DNS.Section
import org.xbill.DNS.Type
import java.io.File
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.util.concurrent.TimeUnit
import okhttp3.OkHttpClient
import okhttp3.Request

/** Opt-in live tests take a user-owned client package from private app data.
 * No production credential or remote address is compiled into the APK. */
@RunWith(AndroidJUnit4::class)
class DeviceTunnelTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private val store get() = (context.applicationContext as TunnelApplication).profiles
    private var activity: android.app.Activity? = null

    private fun await(timeout: Long = 30000, condition: () -> Boolean) {
        val end = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeout)
        while (System.nanoTime() < end) {
            if (condition()) return
            Thread.sleep(100)
        }
        fail("Timed out: " + TunnelState.status.value + "\n" + TunnelState.logs.value.takeLast(20).joinToString("\n"))
    }
    private fun query(type: Int): ByteArray = Message.newQuery(org.xbill.DNS.Record.newRecord(Name.fromString("one.one.one.one."), type, DClass.IN)).toWire()
    private fun permission() {
        val intent = VpnService.prepare(context) ?: return
        // The system identifies the requesting app from the result caller.
        // Starting this dialog as a standalone new task loses that identity.
        instrumentation.runOnMainSync { activity!!.startActivityForResult(intent, 9001) }
        await(60000) { VpnService.prepare(context) == null }
    }
    private fun start(profile: io.github.cysin.sslsockspro.model.TunnelProfile) {
        store.save(profile)
        if (activity == null) activity = instrumentation.startActivitySync(Intent(context, io.github.cysin.sslsockspro.ui.MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        instrumentation.runOnMainSync { activity!!.window.addFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON) }
        Thread.sleep(500)
        if (profile.mode != ConnectionMode.LOCAL_PROXY) permission()
        instrumentation.runOnMainSync { ConnectionService.start(context, profile) }
    }
    private fun textNode(label: String): AccessibilityNodeInfo? {
        fun find(node: AccessibilityNodeInfo): AccessibilityNodeInfo? {
            if (node.text?.toString() == label) return node
            for (index in 0 until node.childCount) {
                node.getChild(index)?.let { find(it)?.let { match -> return match } }
            }
            return null
        }
        return instrumentation.uiAutomation.rootInActiveWindow?.let(::find)
    }

    private fun button(label: String): AccessibilityNodeInfo? {
        var target = textNode(label)
        while (target != null && !target.isClickable) target = target.parent
        return target
    }

    private fun awaitDisconnected() {
        await(15000) {
            TunnelState.status.value.let {
                it.stage == ConnectionStage.IDLE && !it.running && !it.vpnActive
            }
        }
        val manager = context.getSystemService(ConnectivityManager::class.java)
        await(10000) {
            manager.allNetworks.none {
                manager.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
            }
        }
        await(10000) { button("Connect")?.isEnabled == true }
    }

    private fun stop(fromUi: Boolean = false) {
        if (fromUi) {
            instrumentation.waitForIdleSync()
            await(10000) {
                button("Disconnect")?.takeIf { it.isEnabled }
                    ?.performAction(AccessibilityNodeInfo.ACTION_CLICK) == true
            }
        } else instrumentation.runOnMainSync { ConnectionService.stop(context) }
        awaitDisconnected()
    }

    @Test fun savedProfileDisconnectReleasesSystemVpn() {
        assumeTrue("Opt in to using the phone's saved profile",
            InstrumentationRegistry.getArguments().getString("savedProfileTest") == "true")
        val original = store.read()
        val selected = original.profiles.firstOrNull {
            it.id == original.settings.selectedProfileId && it.mode == ConnectionMode.PROXY_VPN
        }
        assumeTrue("Select a working proxy VPN profile on the phone", selected != null)
        try {
            repeat(3) {
                start(selected!!)
                await(60000) { TunnelState.status.value.stage == ConnectionStage.CONNECTED }
                stop(fromUi = true)
            }
            start(selected!!)
            await(10000) { TunnelState.status.value.vpnActive }
            stop(fromUi = true)
        } finally {
            if (TunnelState.status.value.running) runCatching { stop() }
            store.write(original)
        }
    }

    @Test fun realStunnelProxyVpnDnsAndWorkerFailure() {
        val name = InstrumentationRegistry.getArguments().getString("clientFixture")
        assumeTrue("Provide a private clientFixture with tools/device_test.py", name != null)
        val bytes = readTestFixture(name!!)
        val profile = PackageImporter.profiles(PackageImporter.entries(bytes, "client.zip")).single()
            .copy(name = "Phone test server", includedApps = listOf(context.packageName))
        bytes.fill(0)
        Credentials.validate(profile)
        val original = store.read()
        var completed = false
        store.settings(original.settings.copy(reconnect = false))
        try {
            start(profile.copy(mode = ConnectionMode.LOCAL_PROXY))
            await { TunnelState.status.value.stage == ConnectionStage.LISTENING }
            assertFalse(TunnelState.status.value.vpnActive)
            val document = StunnelDocument.parse(profile.config)
            val listener = document.listener(document.sections.first())
            TunneledDns(profile.dnsEndpoint, listener, profile.proxyKind, true).use { dns ->
                assertTrue(Message(dns.resolve(query(Type.A))).header.getCount(Section.ANSWER) > 0)
                assertTrue(Message(dns.resolve(query(Type.AAAA))).header.getCount(Section.ANSWER) > 0)
                assertEquals(0, Message(dns.resolve(query(65))).header.getCount(Section.ANSWER))
            }
            stop()
            permission()
            start(profile.copy(mode = ConnectionMode.PROXY_VPN, includedApps = emptyList()))
            await(60000) { TunnelState.status.value.stage == ConnectionStage.CONNECTED }
            assertTrue(TunnelState.status.value.vpnActive)
            val connectivity = context.getSystemService(android.net.ConnectivityManager::class.java)
            val vpn = connectivity.allNetworks.first { connectivity.getNetworkCapabilities(it)
                ?.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN) == true }
            try {
                assertTrue("Android's VPN DNS resolver must work, not just raw UDP queries",
                    vpn.getAllByName("example.org").isNotEmpty())
            } catch (_: java.net.UnknownHostException) {
                fail("Android VPN DNS failed:\n" + TunnelState.logs.value.takeLast(35).joinToString("\n"))
            }
            assertTrue("Apps' default Android DNS resolver must work with all-app routing",
                InetAddress.getAllByName("example.net").isNotEmpty())
            assertThrows(java.io.IOException::class.java) {
                Socket().use { it.connect(InetSocketAddress(InetAddress.getByName("2606:4700:4700::1111"), 443), 1500) }
            }
            DatagramSocket().use { udp ->
                udp.soTimeout = 15000
                fun request(type: Int): Message {
                    val packet = query(type)
                    udp.send(DatagramPacket(packet, packet.size, InetAddress.getByAddress(byteArrayOf(198.toByte(), 18, 0, 2)), 53))
                    val answer = DatagramPacket(ByteArray(4096), 4096)
                    udp.receive(answer)
                    return Message(answer.data.copyOf(answer.length))
                }
                assertTrue(request(Type.A).header.getCount(Section.ANSWER) > 0)
                assertTrue(request(Type.AAAA).header.getCount(Section.ANSWER) > 0)
                assertEquals(0, request(64).header.getCount(Section.ANSWER))
                assertEquals(0, request(65).header.getCount(Section.ANSWER))
            }
            val client = OkHttpClient.Builder().proxy(Proxy.NO_PROXY).connectTimeout(15, TimeUnit.SECONDS)
                .callTimeout(30, TimeUnit.SECONDS).build()
            try {
                client.newCall(Request.Builder().url("https://cloudflare-dns.com/cdn-cgi/trace").build()).execute().use { response ->
                    assertEquals(200, response.code)
                    assertTrue(response.body!!.string().contains("ip="))
                }
            } finally { client.connectionPool.evictAll(); client.dispatcher.executorService.shutdown() }
            val worker = context.getSystemService(ActivityManager::class.java).runningAppProcesses
                .first { it.processName == context.packageName + ":engine" }
            Process.killProcess(worker.pid)
            await(10000) { TunnelState.status.value.stage == ConnectionStage.ERROR }
            assertTrue("Owner must retain a blocking TUN after worker death", TunnelState.status.value.vpnActive)
            assertThrows(java.io.IOException::class.java) {
                Socket().use { it.connect(InetSocketAddress("1.1.1.1", 443), 2000) }
            }
            start(profile.copy(mode = ConnectionMode.PROXY_VPN))
            await(60000) { TunnelState.status.value.stage == ConnectionStage.CONNECTED }
            stop(fromUi = true)
            completed = true
        } finally {
            if (TunnelState.status.value.running) runCatching { stop() }
            store.write(original)
            val provision = InstrumentationRegistry.getArguments().getString("provisionProfile")
            if (completed && provision != null) store.save(profile.copy(name = provision,
                mode = ConnectionMode.PROXY_VPN, includedApps = emptyList()))
        }
    }
}
