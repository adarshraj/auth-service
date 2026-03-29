package com.authservice.domain

import io.quarkus.hibernate.orm.panache.kotlin.PanacheRepositoryBase
import jakarta.enterprise.context.ApplicationScoped
import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import java.time.Instant

/** Stores the single persisted EC P-256 key pair used for ES256 JWT signing. */
@Entity
@Table(name = "ec_keys")
class EcKeyEntity {
    @Id
    lateinit var id: String

    @Column(nullable = false)
    lateinit var kid: String

    /** PKCS#8 DER bytes, base64-encoded. */
    @Column(name = "private_key_pkcs8", nullable = false, columnDefinition = "TEXT")
    lateinit var privateKeyPkcs8: String

    /** X.509 (SubjectPublicKeyInfo) DER bytes, base64-encoded. */
    @Column(name = "public_key_x509", nullable = false, columnDefinition = "TEXT")
    lateinit var publicKeyX509: String

    @Column(name = "created_at", nullable = false)
    lateinit var createdAt: Instant
}

@ApplicationScoped
class EcKeyRepository : PanacheRepositoryBase<EcKeyEntity, String>
