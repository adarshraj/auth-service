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
    fun deleteExpiredBefore(cutoff: Instant): Long = delete("expiresAt < ?1", cutoff)
}
