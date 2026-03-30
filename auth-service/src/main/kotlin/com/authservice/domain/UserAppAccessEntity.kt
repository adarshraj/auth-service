package com.authservice.domain

import io.quarkus.hibernate.orm.panache.kotlin.PanacheRepository
import jakarta.enterprise.context.ApplicationScoped
import jakarta.persistence.Column
import jakarta.persistence.Embeddable
import jakarta.persistence.EmbeddedId
import jakarta.persistence.Entity
import jakarta.persistence.Table
import java.io.Serializable
import java.time.Instant

@Embeddable
class UserAppAccessId : Serializable {
    @Column(name = "user_id", nullable = false)
    lateinit var userId: String

    @Column(name = "app_id", nullable = false)
    lateinit var appId: String

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is UserAppAccessId) return false
        return userId == other.userId && appId == other.appId
    }

    override fun hashCode(): Int = 31 * userId.hashCode() + appId.hashCode()
}

@Entity
@Table(name = "user_app_access")
class UserAppAccessEntity {
    @EmbeddedId
    lateinit var id: UserAppAccessId

    @Column(nullable = false)
    var role: String = "user"

    @Column(name = "granted_at", nullable = false)
    lateinit var grantedAt: Instant
}

@ApplicationScoped
class UserAppAccessRepository : PanacheRepository<UserAppAccessEntity> {

    fun hasAccess(userId: String, appId: String): Boolean =
        count("id.userId = ?1 and id.appId = ?2", userId, appId) > 0

    fun findByApp(appId: String): List<UserAppAccessEntity> =
        list("id.appId", appId)

    fun findByUser(userId: String): List<UserAppAccessEntity> =
        list("id.userId", userId)

    fun findRole(userId: String, appId: String): String? =
        find("id.userId = ?1 and id.appId = ?2", userId, appId).firstResult()?.role

    fun deleteAccess(userId: String, appId: String): Boolean {
        val entity = find("id.userId = ?1 and id.appId = ?2", userId, appId).firstResult()
            ?: return false
        delete(entity)
        return true
    }
}
