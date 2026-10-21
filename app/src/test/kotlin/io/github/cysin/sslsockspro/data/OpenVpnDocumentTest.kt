package io.github.cysin.sslsockspro.data

import org.junit.Assert.*
import org.junit.Test

class OpenVpnDocumentTest {
    private val profile = "client\nca \"trust bundle.pem\"\n<connection>\nremote vpn.example 1194 udp\n</connection>\n<key>\nprivate-key-payload\n</key>\n"
    @Test fun connectionBlocksAndInlineKeysStayIntact() {
        OpenVpnDocument.validate(profile)
        val text = OpenVpnDocument.runtime(profile, { "/private/" + Credentials.referenceName(it) }, "/private/control.sock", null,
            mapOf("vpn.example" to listOf("192.0.2.1", "2001:db8::1")))
        assertTrue(text.contains("<connection>\nremote \"192.0.2.1\" \"1194\" \"udp\"\n</connection>"))
        assertTrue(text.contains("<key>\nprivate-key-payload\n</key>"))
        assertTrue(text.contains("ca \"/private/trust bundle.pem\""))
        assertTrue(text.contains("remote-cert-tls server"))
        assertEquals(1194, OpenVpnDocument.remotes(profile).single().port)
    }
    @Test fun keyDirectionAndQuotedCredentialPathsArePreserved() {
        val text = OpenVpnDocument.runtime(profile + "tls-auth 'tls key.pem' 1\n", { "/private/file.pem" }, "/private/control.sock", null)
        assertTrue(text.contains("tls-auth \"/private/file.pem\" \"1\""))
        assertTrue(OpenVpnDocument.credentialReferences(profile).contains("trust bundle.pem"))
    }
    @Test fun literalPinnedPeerFingerprintIsNotTreatedAsAFile() {
        val configuration = "remote vpn.example 1194\npeer-fingerprint " + (1..32).joinToString(":") { "AB" } + "\n"
        OpenVpnDocument.validate(configuration)
        val text = OpenVpnDocument.runtime(configuration, { error("No external credential is expected") }, "/private/control.sock", null)
        assertTrue(text.contains("peer-fingerprint AB:AB"))
    }
    @Test fun proxyIsInheritedByConnectionBlocksAndUsesTheAuthenticatedRelay() {
        val text = OpenVpnDocument.runtime(profile, { "/private/file.pem" }, "/private/control.sock",
            OpenVpnDocument.HttpProxyRoute(io.github.cysin.sslsockspro.config.Endpoint("127.0.0.1", 40123), "/private/relay-auth"))
        assertTrue(text.startsWith("pull-filter reject \"http-proxy\"\nproto tcp-client\nhttp-proxy \"127.0.0.1\" 40123 \"/private/relay-auth\" basic\n"))
        assertTrue(text.contains("remote \"vpn.example\" \"1194\" tcp-client"))
        assertFalse(text.contains("1194\" \"udp\""))
    }
    @Test fun unsafeAndIncompleteProfilesFailBeforeStartingNativeCode() {
        for (extra in listOf("plugin injected.so", "up /bin/sh", "dev tap", "compress lz4", "management /bad unix",
            "http-proxy bypass.example 80", "providers injected.so", "replay-persist /private/profiles.enc", "setenv OPENSSL_CONF untrusted")) {
            assertThrows(IllegalArgumentException::class.java) { OpenVpnDocument.validate(profile + extra) }
        }
        assertThrows(IllegalArgumentException::class.java) { OpenVpnDocument.validate(profile + "<connection>") }
        assertThrows(IllegalArgumentException::class.java) { OpenVpnDocument.validate("remote server 1194\n") }
    }
    @Test fun topLevelRemotesExpandToEveryResolvedGatewayAddress() {
        val text = OpenVpnDocument.runtime("client\nca ca.pem\nremote vpn.example 443 tcp\n", { "/private/ca.pem" }, "/private/control.sock", null,
            mapOf("vpn.example" to listOf("192.0.2.1", "2001:db8::1")))
        assertTrue(text.contains("remote \"192.0.2.1\" \"443\" \"tcp\"\nremote \"2001:db8::1\" \"443\" \"tcp\"\n"))
        assertFalse(text.contains("vpn.example"))
    }
    @Test fun deviceIdentifiersAndNestedOptionsCannotBeSentOrApplied() {
        for (extra in listOf("push-peer-info", "setenv UV_DEVICE phone-1", "setenv IV_GUI_VER brand", "setenv-safe iv_sso openurl",
            "setenv opt up /bin/sh", "setenv opt push-peer-info", "setenv opt verb 11", "setenv opt management /x unix")) {
            assertThrows(extra, IllegalArgumentException::class.java) { OpenVpnDocument.validate(profile + extra + "\n") }
        }
        OpenVpnDocument.validate(profile + "setenv opt block-outside-dns\nsetenv FRIENDLY_NAME value\n")
    }
    @Test fun clientCertificatesAreNeverSentWithoutEncryption() {
        assertThrows(IllegalArgumentException::class.java) { OpenVpnDocument.validate(profile + "tls-version-min 1.2\n") }
        assertThrows(IllegalArgumentException::class.java) { OpenVpnDocument.validate(profile + "tls-version-min 1.3 or-highest\n") }
        assertTrue(OpenVpnDocument.runtime(profile, { "/private/file.pem" }, "/private/control.sock", null).contains("tls-version-min 1.3\n"))
        val crypted = profile + "tls-crypt ta.key\ntls-version-min 1.2\n"
        OpenVpnDocument.validate(crypted)
        assertTrue(OpenVpnDocument.runtime(profile + "<tls-crypt>\nkey\n</tls-crypt>\n", { "/private/file.pem" }, "/private/control.sock", null)
            .contains("tls-version-min 1.2\n"))
    }
    @Test fun importedPullFiltersFollowTheAppsRules() {
        val text = OpenVpnDocument.runtime(profile + "pull-filter ignore \"route\"\n", { "/private/file.pem" }, "/private/control.sock", null)
        assertTrue(text.indexOf("pull-filter reject \"http-proxy\"") < text.indexOf("pull-filter ignore \"route\""))
    }
}
