package io.github.cysin.sslsockspro.config

import org.junit.Assert.*
import org.junit.Test

class StunnelDocumentTest {
    @Test fun desktopOptionsIpv6AndRepeatedOptionsSurvive() {
        val source = """
            ; portable client
            foreground = no
            pid = /run/stunnel.pid
            output = /var/log/stunnel.log
            client = yes
            verifyChain = yes
            checkHost = stunnel-server.internal
            sslVersionMin = TLSv1.3
            CAfile = /etc/stunnel/server-ca.crt
            cert = /etc/stunnel/client.pem
            key = /etc/stunnel/client.pem
            sni =
            transparent = none
            socket = l:TCP_NODELAY=1
            socket = r:TCP_NODELAY=1
            [33009]
            accept = 127.0.0.1:33009
            connect = [2001:db8::1]:9983
        """.trimIndent()
        val document = StunnelDocument.parse(source)
        document.validate()
        assertEquals(listOf("33009"), document.sections)
        assertEquals("2001:db8::1", document.remotes("33009").first().host)
        val runtime = document.renderRuntime("/runtime", { "/private/" + it.substringAfterLast('/') })
        assertTrue(runtime.contains("socket = l:TCP_NODELAY=1\nsocket = r:TCP_NODELAY=1"))
        assertTrue(runtime.contains("connect = [2001:db8::1]:9983"))
        assertTrue(runtime.contains("sni =\n"))
        assertFalse(runtime.contains("/etc/stunnel"))
        assertFalse(runtime.contains("/var/log"))
        assertFalse(runtime.contains("foreground = no"))
    }

    @Test fun unverifiedConnectionsAndPublicListenersAreRejected() {
        for (config in listOf(
            StunnelDocument.template("192.0.2.1").replace("verifyChain = yes", "verifyChain = no"),
            StunnelDocument.template("192.0.2.1").replace("127.0.0.1:33009", "0.0.0.0:33009"),
            StunnelDocument.template("192.0.2.1") + "exec = /bin/sh\n",
            StunnelDocument.template("192.0.2.1").replace("TLSv1.3", "TLSv1.2"),
            StunnelDocument.template("192.0.2.1") + "verify = 0\n",
            StunnelDocument.template("192.0.2.1") + "sslVersion = TLSv1.2\n",
            StunnelDocument.template("192.0.2.1") + "setEnv = OPENSSL_CONF=untrusted\n",
            StunnelDocument.template("192.0.2.1") + "securityLevel = 0\n",
        )) assertThrows(ConfigException::class.java) { StunnelDocument.parse(config).validate() }
    }

    @Test fun multipleServicesUseGlobalDefaultsAndKeepTheirOwnRemotes() {
        val source = StunnelDocument.template("192.0.2.1") + "\n[socks]\naccept = [::1]:33010\nconnect = 192.0.2.1:9984\n"
        val document = StunnelDocument.parse(source)
        document.validate()
        assertEquals(2, document.sections.size)
        assertEquals("::1", document.listener("socks").host)
        assertEquals(9984, document.remotes("socks").first().port)
    }

    @Test fun resolvedGatewayAddressesBecomeOrderedFailoverConnections() {
        val document = StunnelDocument.parse(StunnelDocument.template("gateway.example"))
        val runtime = document.renderRuntime("/runtime", { "/private/$it" }, mapOf("gateway.example" to listOf("192.0.2.1", "2001:db8::1")))
        assertTrue(runtime.contains("connect = 192.0.2.1:9983\nconnect = [2001:db8::1]:9983\n"))
        assertFalse(runtime.contains("gateway.example"))
    }

    @Test fun gatewayPlansKeepPreferredAddressesAndAllowOnlyResolvedPeers() {
        val plan = GatewayPlan.create(listOf(Endpoint("gateway.example", 9983), Endpoint("gateway.example", 9984), Endpoint("192.0.2.9", 443))) { host ->
            if (host == "gateway.example") listOf("fe80::1%wlan0", "192.0.2.1", "192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4") else listOf(host)
        }
        assertEquals(listOf("fe80::1", "192.0.2.1", "192.0.2.2", "192.0.2.3"), plan.hosts["gateway.example"])
        assertTrue("fe80::1|9984" in plan.allowed && "192.0.2.3|9983" in plan.allowed && "192.0.2.9|443" in plan.allowed)
        assertFalse(plan.allowed.any { it.startsWith("192.0.2.4") })
        assertEquals(plan, GatewayPlan.decode(plan.encode()))
        assertThrows(IllegalArgumentException::class.java) { GatewayPlan.create(listOf(Endpoint("missing.example", 1))) { emptyList() } }
    }

    @Test fun vpnModesReplaceOnlyTheSelectedListener() {
        val source = StunnelDocument.template("192.0.2.1") + "\n[ssh]\naccept = 127.0.0.1:2222\nconnect = 192.0.2.1:22\n"
        val runtime = StunnelDocument.parse(source).renderRuntime("/runtime", { "/private/$it" }, listeners = mapOf("proxy" to Endpoint("127.0.0.1", 40001)))
        assertTrue(runtime.contains("[proxy]\naccept = 127.0.0.1:40001\n"))
        assertFalse(runtime.contains("accept = 127.0.0.1:33009"))
        assertTrue(runtime.contains("accept = 127.0.0.1:2222"))
        assertThrows(IllegalArgumentException::class.java) {
            StunnelDocument.parse(source).renderRuntime("/runtime", { it }, listeners = mapOf("proxy" to Endpoint("0.0.0.0", 40001)))
        }
    }
}
