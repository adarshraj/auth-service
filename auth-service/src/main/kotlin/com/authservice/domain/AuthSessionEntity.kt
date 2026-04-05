package com.authservice.domain

import io.quarkus.hibernate.orm.panache.kotlin.PanacheRepositoryBase
import jakarta.enterprise.context.ApplicationScoped
import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import java.time.Instant

/**
 * Server-side SSO session. The raw session id lives only in the client's `auth_session`
 * cookie; this row stores `HMAC(raw, token-pepper)` so a DB dump can't forge a cookie.
 */
@Entity
@Table(name = "auth_sessions")
class AuthSessionEntity {
    @Id
    lateinit var id: String

    @Column(name = "user_id", nullable = false)
    lateinit var userId: String

    @Column(name = "expires_at", nullable = false)
    lateinit var expiresAt: Instant

    @Column(name = "created_at", nullable = false)
    lateinit var createdAt: Instant
}

@ApplicationScoped
class AuthSessionRepository : PanacheRepositoryBase<AuthSessionEntity, String> {
    fun findValid(hashedId: String, now: Instant): AuthSessionEntity? =
        find("id = ?1 and expiresAt > ?2", hashedId, now).firstResult()

    fun deleteByHashedId(hashedId: String): Boolean = delete("id", hashedId) > 0

    fun deleteExpiredBefore(cutoff: Instant): Long = delete("expiresAt < ?1", cutoff)
}
