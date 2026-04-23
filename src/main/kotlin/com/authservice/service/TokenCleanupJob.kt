package com.authservice.service

import com.authservice.domain.AuthTokenRepository
import com.authservice.domain.OAuthCodeRepository
import com.authservice.domain.RefreshTokenRepository
import io.quarkus.scheduler.Scheduled
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import jakarta.transaction.Transactional
import org.jboss.logging.Logger
import java.time.Instant
import java.time.temporal.ChronoUnit

/** Purges used/expired tokens. Runs nightly. */
@ApplicationScoped
class TokenCleanupJob @Inject constructor(
    private val authTokenRepository: AuthTokenRepository,
    private val oauthCodeRepository: OAuthCodeRepository,
    private val refreshTokenRepository: RefreshTokenRepository,
) {
    companion object {
        private val log: Logger = Logger.getLogger(TokenCleanupJob::class.java)
    }

    @Scheduled(cron = "0 0 3 * * ?")  // 03:00 UTC daily
    @Transactional
    fun cleanup() {
        val longCutoff = Instant.now().minus(30, ChronoUnit.DAYS)
        val deleted = authTokenRepository.deleteExpiredBefore(longCutoff)
        if (deleted > 0) log.infof("Purged %d expired auth tokens", deleted)

        // OAuth codes are only valid for 60 seconds; purge anything older than 1 day
        val codeCutoff = Instant.now().minus(1, ChronoUnit.DAYS)
        val deletedCodes = oauthCodeRepository.deleteExpiredBefore(codeCutoff)
        if (deletedCodes > 0) log.infof("Purged %d expired oauth codes", deletedCodes)

        // Refresh tokens expire after 7 days; purge anything older than 14 days
        val refreshCutoff = Instant.now().minus(14, ChronoUnit.DAYS)
        val deletedRefresh = refreshTokenRepository.deleteExpiredBefore(refreshCutoff)
        if (deletedRefresh > 0) log.infof("Purged %d expired refresh tokens", deletedRefresh)
    }
}
