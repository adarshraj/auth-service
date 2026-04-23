package com.authservice.security

import io.quarkus.scheduler.Scheduled
import jakarta.enterprise.context.ApplicationScoped
import java.util.concurrent.ConcurrentHashMap

/**
 * In-memory store for single-use OAuth state nonces.
 *
 * Each nonce is registered when the OAuth redirect is initiated and consumed
 * (removed atomically) when the callback arrives. This prevents CSRF and
 * state-replay attacks: a valid HMAC signature alone is not enough — the nonce
 * must also be present in this store, meaning the flow was started on this
 * server instance.
 *
 * TTL is 10 minutes — OAuth flows should complete well within that window.
 * Stale entries are evicted every 5 minutes to bound memory usage.
 */
@ApplicationScoped
class OAuthNonceStore {

    // nonce → expiry epoch ms
    private val nonces = ConcurrentHashMap<String, Long>()
    private val ttlMs = 600_000L // 10 minutes

    fun register(nonce: String) {
        nonces[nonce] = System.currentTimeMillis() + ttlMs
    }

    /**
     * Consumes the nonce: removes it and returns true if it existed and has not expired.
     * Returns false (and does NOT re-insert) if missing or expired — any subsequent
     * call with the same nonce will also return false.
     */
    fun consume(nonce: String): Boolean {
        val expiry = nonces.remove(nonce) ?: return false
        return System.currentTimeMillis() <= expiry
    }

    @Scheduled(every = "5m")
    fun evictExpired() {
        val now = System.currentTimeMillis()
        nonces.entries.removeIf { it.value < now }
    }
}
