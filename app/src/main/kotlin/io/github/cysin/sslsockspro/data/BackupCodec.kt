package io.github.cysin.sslsockspro.data

import java.nio.ByteBuffer
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/** Portable authenticated backups: fixed KDF parameters, random salt and nonce. */
object BackupCodec {
    private val magic = "SSPBK001".toByteArray(Charsets.US_ASCII)
    private const val ITERATIONS = 600_000
    const val MAX_BYTES = 32 * 1024 * 1024
    private val random = SecureRandom()

    private fun key(password: CharArray, salt: ByteArray): SecretKeySpec {
        require(password.size >= 12) { "Use a backup password with at least 12 characters" }
        val specification = PBEKeySpec(password, salt, ITERATIONS, 256)
        return try { SecretKeySpec(SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(specification).encoded, "AES") }
        finally { specification.clearPassword() }
    }

    fun encrypt(clear: ByteArray, password: CharArray): ByteArray {
        require(clear.size <= MAX_BYTES) { "Backup exceeds 32 MiB" }
        val salt = ByteArray(16).also(random::nextBytes)
        val nonce = ByteArray(12).also(random::nextBytes)
        val header = magic + salt + nonce
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key(password, salt), GCMParameterSpec(128, nonce))
        cipher.updateAAD(header)
        return header + cipher.doFinal(clear)
    }

    fun decrypt(encrypted: ByteArray, password: CharArray): ByteArray {
        require(encrypted.size in 52..MAX_BYTES + 52 && encrypted.copyOfRange(0, 8).contentEquals(magic)) { "Not a supported encrypted backup" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(password, encrypted.copyOfRange(8, 24)), GCMParameterSpec(128, encrypted.copyOfRange(24, 36)))
        cipher.updateAAD(encrypted.copyOfRange(0, 36))
        return cipher.doFinal(encrypted, 36, encrypted.size - 36)
    }
}
