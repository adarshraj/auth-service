package com.authservice.domain

import io.quarkus.hibernate.orm.panache.kotlin.PanacheRepositoryBase
import jakarta.enterprise.context.ApplicationScoped
import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import java.time.Instant

@Entity
@Table(name = "apps")
class AppEntity {
    @Id
    lateinit var id: String

    @Column(nullable = false)
    lateinit var name: String

    /** If true: login is blocked unless the user has a row in user_app_access for this app. */
    @Column(name = "requires_explicit_access", nullable = false)
    var requiresExplicitAccess: Boolean = false

    /** Newline-separated list of allowed redirect URIs for OAuth browser flows. Null = none registered. */
    @Column(name = "redirect_uris")
    var redirectUris: String? = null

    @Column(name = "created_at", nullable = false)
    lateinit var createdAt: Instant

    fun allowedRedirectUris(): List<String> =
        redirectUris?.lines()?.map { it.trim() }?.filter { it.isNotEmpty() } ?: emptyList()
}

@ApplicationScoped
class AppRepository : PanacheRepositoryBase<AppEntity, String> {
    fun countAll(): Long = count()
}
