package com.authservice.service

import com.authservice.domain.AuthTokenRepository
import io.quarkus.scheduler.Scheduled
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import jakarta.transaction.Transactional
import org.jboss.logging.Logger
import java.time.Instant
import java.time.temporal.ChronoUnit

/** Purges used/expired auth tokens older than 30 days. Runs nightly. */
@ApplicationScoped
class TokenCleanupJob @Inject constructor(
    private val authTokenRepository: AuthTokenRepository,
) {
    companion object {
        private val log: Logger = Logger.getLogger(TokenCleanupJob::class.java)
    }

    @Scheduled(cron = "0 0 3 * * ?")  // 03:00 UTC daily
    @Transactional
    fun cleanup() {
        val cutoff = Instant.now().minus(30, ChronoUnit.DAYS)
        val deleted = authTokenRepository.deleteExpiredBefore(cutoff)
        if (deleted > 0) log.infof("Purged %d expired auth tokens", deleted)
    }
}
