package com.authservice.service

import jakarta.enterprise.context.ApplicationScoped
import java.nio.ByteBuffer
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * TOTP (RFC 6238) implementation using only JDK crypto.
 * Generates and verifies 6-digit time-based one-time passwords with HMAC-SHA1.
 */
@ApplicationScoped
class TotpService {

    companion object {
        private const val DIGITS = 6
        private const val PERIOD_SECONDS = 30L
        private const val SECRET_BYTES = 20 // 160-bit secret
        private const val SKEW = 1 // allow ±1 time step (30s window each side)
        private const val BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        private val secureRandom = SecureRandom()
    }

    /** Generate a new base32-encoded secret. */
    fun generateSecret(): String {
        val bytes = ByteArray(SECRET_BYTES)
        secureRandom.nextBytes(bytes)
        return base32Encode(bytes)
    }

    /** Build an otpauth:// URI for QR code scanning. */
    fun buildOtpAuthUri(secret: String, email: String, issuer: String = "AuthService"): String {
        val encodedIssuer = java.net.URLEncoder.encode(issuer, "UTF-8")
        val encodedEmail = java.net.URLEncoder.encode(email, "UTF-8")
        return "otpauth://totp/$encodedIssuer:$encodedEmail?secret=$secret&issuer=$encodedIssuer&algorithm=SHA1&digits=$DIGITS&period=$PERIOD_SECONDS"
    }

    /** Verify a TOTP code against a secret, allowing ±1 time step skew. */
    fun verify(secret: String, code: String): Boolean {
        if (code.length != DIGITS || !code.all { it.isDigit() }) return false
        val secretBytes = base32Decode(secret)
        val currentStep = System.currentTimeMillis() / 1000 / PERIOD_SECONDS
        for (offset in -SKEW..SKEW) {
            val expected = generateCode(secretBytes, currentStep + offset)
            if (timingSafeEquals(code, expected)) return true
        }
        return false
    }

    /** Generate recovery codes (8 codes, 8 chars each). */
    fun generateRecoveryCodes(): List<String> {
        val chars = "abcdefghijklmnopqrstuvwxyz0123456789"
        return (1..8).map {
            (1..8).map { chars[secureRandom.nextInt(chars.length)] }.joinToString("")
        }
    }

    private fun generateCode(secretBytes: ByteArray, timeStep: Long): String {
        val data = ByteBuffer.allocate(8).putLong(timeStep).array()
        val mac = Mac.getInstance("HmacSHA1")
        mac.init(SecretKeySpec(secretBytes, "HmacSHA1"))
        val hash = mac.doFinal(data)

        val offset = hash[hash.size - 1].toInt() and 0x0F
        val binary = ((hash[offset].toInt() and 0x7F) shl 24) or
            ((hash[offset + 1].toInt() and 0xFF) shl 16) or
            ((hash[offset + 2].toInt() and 0xFF) shl 8) or
            (hash[offset + 3].toInt() and 0xFF)

        val otp = binary % Math.pow(10.0, DIGITS.toDouble()).toInt()
        return otp.toString().padStart(DIGITS, '0')
    }

    private fun timingSafeEquals(a: String, b: String): Boolean {
        if (a.length != b.length) return false
        var result = 0
        for (i in a.indices) {
            result = result or (a[i].code xor b[i].code)
        }
        return result == 0
    }

    private fun base32Encode(data: ByteArray): String {
        val sb = StringBuilder()
        var buffer = 0
        var bitsLeft = 0
        for (byte in data) {
            buffer = (buffer shl 8) or (byte.toInt() and 0xFF)
            bitsLeft += 8
            while (bitsLeft >= 5) {
                bitsLeft -= 5
                sb.append(BASE32_CHARS[(buffer shr bitsLeft) and 0x1F])
            }
        }
        if (bitsLeft > 0) {
            sb.append(BASE32_CHARS[(buffer shl (5 - bitsLeft)) and 0x1F])
        }
        return sb.toString()
    }

    private fun base32Decode(encoded: String): ByteArray {
        val data = encoded.uppercase()
        val output = mutableListOf<Byte>()
        var buffer = 0
        var bitsLeft = 0
        for (ch in data) {
            val value = BASE32_CHARS.indexOf(ch)
            if (value < 0) continue
            buffer = (buffer shl 5) or value
            bitsLeft += 5
            if (bitsLeft >= 8) {
                bitsLeft -= 8
                output.add((buffer shr bitsLeft).toByte())
            }
        }
        return output.toByteArray()
    }
}
