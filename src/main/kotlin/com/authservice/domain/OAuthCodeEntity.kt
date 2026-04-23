package com.authservice.domain

import io.quarkus.hibernate.orm.panache.kotlin.PanacheRepositoryBase
import jakarta.enterprise.context.ApplicationScoped
import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import java.time.Instant

/** Short-lived one-time code issued after OAuth callback. Exchanged for a JWT via POST /auth/token. */
@Entity
@Table(name = "oauth_codes")
class OAuthCodeEntity {
    @Id
    lateinit var id: String

    @Column(nullable = false, unique = true)
    lateinit var code: String

    @Column(name = "user_id", nullable = false)
    lateinit var userId: String

    @Column(nullable = false)
    lateinit var email: String

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
class OAuthCodeRepository : PanacheRepositoryBase<OAuthCodeEntity, String> {
    fun findByCode(code: String): OAuthCodeEntity? = find("code", code).firstResult()

    /**
     * Atomically marks the code as used and returns it — or returns null if the code
     * doesn't exist, is already used, or has expired.
     *
     * Uses an UPDATE-before-SELECT pattern to eliminate the TOCTOU race where two
     * concurrent requests could both read `used=false`, both proceed, and both produce
     * a JWT from the same one-time code. Only the request whose UPDATE affects 1 row wins.
     */
    fun claimCode(code: String): OAuthCodeEntity? {
        val updated = update("used = true WHERE code = ?1 AND used = false AND expiresAt > ?2",
            code, Instant.now())
        if (updated == 0) return null
        return find("code", code).firstResult()
    }

    fun deleteExpiredBefore(cutoff: Instant): Long = delete("expiresAt < ?1", cutoff)
}
