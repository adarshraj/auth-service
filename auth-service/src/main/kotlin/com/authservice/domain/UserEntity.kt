package com.authservice.domain

import io.quarkus.hibernate.orm.panache.kotlin.PanacheRepositoryBase
import jakarta.enterprise.context.ApplicationScoped
import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import java.time.Instant

@Entity
@Table(name = "users")
class UserEntity {
    @Id
    lateinit var id: String

    @Column(nullable = false, unique = true)
    lateinit var email: String

    var name: String? = null

    @Column(name = "password_hash")
    var passwordHash: String? = null

    @Column(name = "avatar_url")
    var avatarUrl: String? = null

    @Column(name = "oauth_provider")
    var oauthProvider: String? = null

    @Column(name = "oauth_id")
    var oauthId: String? = null

    @Column(name = "email_verified", nullable = false)
    var emailVerified: Boolean = false

    @Column(name = "mfa_enabled", nullable = false)
    var mfaEnabled: Boolean = false

    @Column(name = "mfa_secret")
    var mfaSecret: String? = null

    @Column(name = "mfa_backup_codes")
    var mfaBackupCodes: String? = null

    @Column(name = "created_at", nullable = false)
    lateinit var createdAt: Instant

    @Column(name = "updated_at", nullable = false)
    lateinit var updatedAt: Instant
}

@ApplicationScoped
class UserRepository : PanacheRepositoryBase<UserEntity, String> {

    fun findByEmail(email: String): UserEntity? =
        find("email", email.lowercase().trim()).firstResult()

    fun findByOAuth(provider: String, oauthId: String): UserEntity? =
        find("oauthProvider = ?1 and oauthId = ?2", provider, oauthId).firstResult()
}
