package io.github.cysin.sslsockspro.privacy

import org.junit.After
import org.junit.Assert.*
import org.junit.Test

class RedactorTest {
    @After fun reset() = Redactor.sensitiveNames(emptyList())

    @Test fun publicAddressesHardwareAddressesAndSubjectsAreRemoved() {
        val line = "2026.10.21 04:28:35 LOG5[0]: Peer Connection Initiated with [AF_INET]203.0.113.7:443 " +
            "local [2001:db8::42]:51000 mac 02:00:5e:10:00:01 VERIFY OK: depth=0, CN=Alice Example, O=Home, emailAddress=alice@example.org"
        val redacted = Redactor.redact(line)
        assertFalse(redacted.contains("203.0.113.7") || redacted.contains("2001:db8::42") || redacted.contains("02:00:5e"))
        assertFalse(redacted.contains("Alice") || redacted.contains("alice@example.org") || redacted.contains("Home"))
        assertTrue("Timestamps and ports remain readable", redacted.startsWith("2026.10.21 04:28:35") && redacted.contains("[address]:443"))
    }

    @Test fun syntheticAndLoopbackAddressesStayReadable() {
        val line = "listening on 127.0.0.1:33009 and [::1]:33010; tunnel 198.18.0.1 dns 198.18.0.2 v6 fd00:5353::1 mask 255.255.255.252"
        assertEquals(line, Redactor.redact(line))
        assertEquals("stunnel 5.82 OpenSSL 4.0.3", Redactor.redact("stunnel 5.82 OpenSSL 4.0.3"))
    }

    @Test fun gatewayNamesPathsAndCredentialLinesAreRedacted() {
        Redactor.sensitiveNames(listOf("gateway.example.net", "192.0.2.1"))
        assertEquals("connect to [gateway]:9983", Redactor.redact("connect to Gateway.Example.NET:9983"))
        assertEquals("reading [private path]", Redactor.redact("reading /data/user/0/io.github.cysin.sslsockspro/no_backup/runtime/x.pem"))
        assertEquals("[credential-related diagnostic redacted]", Redactor.redact("Enter Private Key Password:"))
        assertEquals("This private key needs a passphrase", Redactor.redactIdentifiers("This private key needs a passphrase"))
    }
}
