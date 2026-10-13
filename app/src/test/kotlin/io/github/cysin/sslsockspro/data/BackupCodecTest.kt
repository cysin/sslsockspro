package io.github.cysin.sslsockspro.data

import org.junit.Assert.*
import org.junit.Test
import javax.crypto.AEADBadTagException

class BackupCodecTest {
    @Test fun backupsArePortableAuthenticatedAndRandomized() {
        val content = "private profile and credential canary".toByteArray()
        val password = "correct backup password".toCharArray()
        val one = BackupCodec.encrypt(content, password)
        val two = BackupCodec.encrypt(content, password)
        assertFalse(one.contentEquals(two))
        assertArrayEquals(content, BackupCodec.decrypt(one, password))
        assertThrows(AEADBadTagException::class.java) { BackupCodec.decrypt(one, "incorrect password value".toCharArray()) }
        one[one.lastIndex] = (one.last().toInt() xor 1).toByte()
        assertThrows(AEADBadTagException::class.java) { BackupCodec.decrypt(one, password) }
    }
    @Test fun shortPasswordsAndMalformedHeadersAreRejected() {
        assertThrows(IllegalArgumentException::class.java) { BackupCodec.encrypt(byteArrayOf(1), "short".toCharArray()) }
        assertThrows(IllegalArgumentException::class.java) { BackupCodec.decrypt(ByteArray(100), "valid password phrase".toCharArray()) }
    }
}
