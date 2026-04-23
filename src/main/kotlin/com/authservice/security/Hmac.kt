package com.authservice.security

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Pure-function HMAC-SHA256 utilities.
 * Each call site injects its own purpose-specific secret so that a leak of one
 * secret does not compromise the other HMAC uses (state signing, token pepper, admin key).
 */
object Hmac {
    fun sha256(data: String, secret: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(secret.toByteArray(StandardCharsets.UTF_8), "HmacSHA256"))
        return mac.doFinal(data.toByteArray(StandardCharsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
    }

    /** Constant-time comparison — prevents timing attacks on HMAC verification. */
    fun verify(data: String, expected: String, secret: String): Boolean {
        val computed = sha256(data, secret).toByteArray(StandardCharsets.UTF_8)
        return MessageDigest.isEqual(computed, expected.toByteArray(StandardCharsets.UTF_8))
    }
}
