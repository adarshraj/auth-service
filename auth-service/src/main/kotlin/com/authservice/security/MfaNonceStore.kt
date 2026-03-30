package com.authservice.security

import io.quarkus.scheduler.Scheduled
import jakarta.enterprise.context.ApplicationScoped
import java.util.concurrent.ConcurrentHashMap

/**
 * In-memory store for single-use MFA challenge nonces.
 *
 * Each nonce is registered when an MFA challenge token is issued (after successful
 * password/OAuth verification) and consumed when the user completes MFA verification.
 * This prevents replay of MFA tokens within their TTL.
 *
 * TTL is 5 minutes — matches the MFA token expiry.
 * Stale entries are evicted every 2 minutes to bound memory usage.
 */
@ApplicationScoped
class MfaNonceStore {

    // nonce → expiry epoch ms
    private val nonces = ConcurrentHashMap<String, Long>()
    private val ttlMs = 300_000L // 5 minutes

    fun register(nonce: String) {
        nonces[nonce] = System.currentTimeMillis() + ttlMs
    }

    /**
     * Consumes the nonce: removes it and returns true if it existed and has not expired.
     * Returns false if missing or expired — any subsequent call with the same nonce
     * will also return false, enforcing single-use semantics.
     */
    fun consume(nonce: String): Boolean {
        val expiry = nonces.remove(nonce) ?: return false
        return System.currentTimeMillis() <= expiry
    }

    @Scheduled(every = "2m")
    fun evictExpired() {
        val now = System.currentTimeMillis()
        nonces.entries.removeIf { it.value < now }
    }
}
