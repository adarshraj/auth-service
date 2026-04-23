package com.authservice.security

import jakarta.enterprise.context.ApplicationScoped
import org.eclipse.microprofile.config.inject.ConfigProperty
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * HMAC-SHA256 hashing — copied from DocBucket's ApiKeyHasher.
 * Used here to hash the admin key before constant-time comparison.
 */
@ApplicationScoped
class ApiKeyHasher(
    @ConfigProperty(name = "auth.key-hmac-secret") private val hmacSecret: String,
) {
    private val secretKey: SecretKeySpec by lazy {
        SecretKeySpec(hmacSecret.toByteArray(StandardCharsets.UTF_8), "HmacSHA256")
    }

    fun hash(rawKey: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(secretKey)
        return mac.doFinal(rawKey.toByteArray(StandardCharsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
    }

    fun verify(rawKey: String, storedHash: String): Boolean {
        val computed = hash(rawKey).toByteArray(StandardCharsets.UTF_8)
        val stored = storedHash.toByteArray(StandardCharsets.UTF_8)
        return MessageDigest.isEqual(computed, stored)
    }
}
