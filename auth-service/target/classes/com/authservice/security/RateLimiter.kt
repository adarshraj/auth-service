package com.authservice.security

import com.authservice.config.RateLimitConfig
import io.quarkus.scheduler.Scheduled
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/** Fixed-window rate limiter — copied from DocBucket's RateLimiter. */
@ApplicationScoped
class RateLimiter @Inject constructor(
    private val rateLimitConfig: RateLimitConfig,
) {
    private data class Window(val startMs: Long, val count: AtomicInteger)

    private val windows = ConcurrentHashMap<String, Window>()
    private val windowMs = 60_000L

    fun tryAcquire(key: String): Boolean {
        if (!rateLimitConfig.enabled()) return true
        val now = System.currentTimeMillis()
        val window = windows.compute(key) { _, existing ->
            if (existing == null || now - existing.startMs > windowMs) {
                Window(now, AtomicInteger(0))
            } else {
                existing
            }
        }!!
        return window.count.incrementAndGet() <= rateLimitConfig.requestsPerMinute()
    }

    @Scheduled(every = "2m")
    fun evictStaleWindows() {
        val cutoff = System.currentTimeMillis() - windowMs * 2
        windows.entries.removeIf { it.value.startMs < cutoff }
    }
}
