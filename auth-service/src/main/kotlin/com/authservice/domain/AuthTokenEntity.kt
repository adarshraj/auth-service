package com.authservice.domain

import io.quarkus.hibernate.orm.panache.kotlin.PanacheRepositoryBase
import jakarta.enterprise.context.ApplicationScoped
import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import java.time.Instant

/** Single-use tokens for password reset, magic link, email verification. */
@Entity
@Table(name = "auth_tokens")
class AuthTokenEntity {
    @Id
    lateinit var id: String

    @Column(name = "user_id", nullable = false)
    lateinit var userId: String

    @Column(nullable = false, unique = true)
    lateinit var token: String

    /** 'password_reset' | 'magic_link' | 'email_verification' */
    @Column(nullable = false)
    lateinit var type: String

    @Column(name = "app_id")
    var appId: String? = null

    @Column(name = "expires_at", nullable = false)
    lateinit var expiresAt: Instant

    @Column(nullable = false)
    var used: Boolean = false

    @Column(name = "created_at", nullable = false)
    lateinit var createdAt: Instant
}

@ApplicationScoped
class AuthTokenRepository : PanacheRepositoryBase<AuthTokenEntity, String> {

    fun findByToken(token: String): AuthTokenEntity? =
        find("token", token).firstResult()

    /**
     * Atomically claims a token: marks it used and returns the entity — or returns null
     * if the token doesn't exist, is already used, has the wrong type, or has expired.
     * Uses UPDATE-before-SELECT to eliminate the TOCTOU race (same pattern as OAuthCodeRepository.claimCode).
     */
    fun claimToken(tokenHash: String, expectedType: String): AuthTokenEntity? {
        val updated = update(
            "used = true WHERE token = ?1 AND type = ?2 AND used = false AND expiresAt > ?3",
            tokenHash, expectedType, Instant.now(),
        )
        if (updated == 0) return null
        return find("token", tokenHash).firstResult()
    }

    /** Remove tokens older than 30 days to keep the table lean. */
    fun deleteExpiredBefore(cutoff: Instant): Long =
        delete("expiresAt < ?1", cutoff)
}
