package com.authservice.domain

import io.quarkus.hibernate.orm.panache.kotlin.PanacheRepositoryBase
import jakarta.enterprise.context.ApplicationScoped
import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import java.time.Instant

/** Refresh token — hashed at rest, revocable, 7-day TTL. */
@Entity
@Table(name = "refresh_tokens")
class RefreshTokenEntity {
    @Id
    lateinit var id: String

    @Column(name = "user_id", nullable = false)
    lateinit var userId: String

    @Column(nullable = false, unique = true)
    lateinit var token: String

    @Column(name = "app_id")
    var appId: String? = null

    @Column(name = "expires_at", nullable = false)
    lateinit var expiresAt: Instant

    @Column(nullable = false)
    var revoked: Boolean = false

    @Column(name = "created_at", nullable = false)
    lateinit var createdAt: Instant
}

@ApplicationScoped
class RefreshTokenRepository : PanacheRepositoryBase<RefreshTokenEntity, String> {

    /**
     * Atomically claims a refresh token: marks it revoked and returns the entity.
     * Returns null if the token doesn't exist, is already revoked, or has expired.
     * Each refresh token is single-use — exchanging it issues a new one (rotation).
     */
    fun claimToken(tokenHash: String): RefreshTokenEntity? {
        val updated = update(
            "revoked = true WHERE token = ?1 AND revoked = false AND expiresAt > ?2",
            tokenHash, Instant.now(),
        )
        if (updated == 0) return null
        return find("token", tokenHash).firstResult()
    }

    /** Revoke all refresh tokens for a user (e.g., on account deletion or password change). */
    fun revokeAllForUser(userId: String): Int =
        update("revoked = true WHERE userId = ?1 AND revoked = false", userId)

    /** Remove expired/revoked tokens older than the given cutoff. */
    fun deleteExpiredBefore(cutoff: Instant): Long =
        delete("expiresAt < ?1", cutoff)
}
