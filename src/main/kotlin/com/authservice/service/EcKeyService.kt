package com.authservice.service

import com.authservice.domain.EcKeyEntity
import com.authservice.domain.EcKeyRepository
import io.quarkus.runtime.StartupEvent
import jakarta.enterprise.context.ApplicationScoped
import jakarta.enterprise.event.Observes
import jakarta.inject.Inject
import jakarta.transaction.Transactional
import org.jboss.logging.Logger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.time.Instant
import java.util.Base64
import java.util.UUID

/**
 * Manages the EC P-256 key pair used for ES256 JWT signing.
 * On first startup the key pair is generated and persisted; subsequent startups load it.
 * Exposes the public key as a JWK map for the /.well-known/jwks.json endpoint.
 */
@ApplicationScoped
class EcKeyService @Inject constructor(
    private val ecKeyRepository: EcKeyRepository,
) {
    companion object {
        private val log: Logger = Logger.getLogger(EcKeyService::class.java)
        private const val ROW_ID = "primary"
        private const val FIELD_SIZE = 32 // P-256 coordinate size in bytes
    }

    private lateinit var _privateKey: ECPrivateKey
    private lateinit var _publicKey: ECPublicKey
    private lateinit var _kid: String

    val privateKey: ECPrivateKey get() = _privateKey
    val publicKey: ECPublicKey get() = _publicKey
    val kid: String get() = _kid

    @Transactional
    fun onStart(@Observes ev: StartupEvent) {
        val existing = ecKeyRepository.findById(ROW_ID)
        if (existing != null) {
            val kf = KeyFactory.getInstance("EC")
            _privateKey = kf.generatePrivate(
                PKCS8EncodedKeySpec(Base64.getDecoder().decode(existing.privateKeyPkcs8))
            ) as ECPrivateKey
            _publicKey = kf.generatePublic(
                X509EncodedKeySpec(Base64.getDecoder().decode(existing.publicKeyX509))
            ) as ECPublicKey
            _kid = existing.kid
            log.infof("Loaded EC P-256 key pair from DB (kid=%s)", _kid)
        } else {
            val kpg = KeyPairGenerator.getInstance("EC")
            kpg.initialize(ECGenParameterSpec("secp256r1"))
            val kp = kpg.generateKeyPair()
            _privateKey = kp.private as ECPrivateKey
            _publicKey = kp.public as ECPublicKey
            _kid = UUID.randomUUID().toString()

            ecKeyRepository.persist(EcKeyEntity().apply {
                id = ROW_ID
                kid = _kid
                privateKeyPkcs8 = Base64.getEncoder().encodeToString(_privateKey.encoded)
                publicKeyX509 = Base64.getEncoder().encodeToString(_publicKey.encoded)
                createdAt = Instant.now()
            })
            log.infof("Generated and persisted new EC P-256 key pair (kid=%s)", _kid)
        }
    }

    /** Returns the public key as a JWK object map suitable for a JWKS response. */
    fun publicKeyAsJwk(): Map<String, Any> {
        val point = publicKey.w
        val xBytes = padOrTrim(point.affineX.toByteArray(), FIELD_SIZE)
        val yBytes = padOrTrim(point.affineY.toByteArray(), FIELD_SIZE)
        val enc = Base64.getUrlEncoder().withoutPadding()
        return mapOf(
            "kty" to "EC",
            "crv" to "P-256",
            "x" to enc.encodeToString(xBytes),
            "y" to enc.encodeToString(yBytes),
            "use" to "sig",
            "alg" to "ES256",
            "kid" to kid,
        )
    }

    /** BigInteger.toByteArray() may include a leading zero sign byte or be shorter than fieldSize. */
    private fun padOrTrim(bytes: ByteArray, size: Int): ByteArray = when {
        bytes.size == size -> bytes
        bytes.size > size  -> bytes.copyOfRange(bytes.size - size, bytes.size)
        else               -> ByteArray(size - bytes.size) + bytes
    }
}
