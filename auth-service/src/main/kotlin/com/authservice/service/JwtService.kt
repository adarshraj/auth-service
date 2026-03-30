package com.authservice.service

import io.jsonwebtoken.JwtException
import io.jsonwebtoken.Jwts
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import org.eclipse.microprofile.config.inject.ConfigProperty
import org.jboss.logging.Logger
import java.util.Date

/**
 * JWT sign/verify using ES256 (ECDSA P-256).
 * Token payload: { sub, userId, email, iss, iat, exp [, appId, aud, groups] }
 *
 * - `aud`    — set to appId when present; consuming services must validate to prevent cross-app token reuse.
 * - `groups` — set to [role] (e.g. ["user"] or ["admin"]) when a role is provided; read by
 *              Quarkus/MP-JWT for @RolesAllowed. Only present when the token is app-scoped.
 *
 * The public key is published at /.well-known/jwks.json so consuming services
 * can verify tokens without sharing a secret.
 */
@ApplicationScoped
class JwtService @Inject constructor(
    private val ecKeyService: EcKeyService,
    @ConfigProperty(name = "auth.jwt.expiry-seconds", defaultValue = "604800") private val expirySeconds: Long,
    @ConfigProperty(name = "auth.base-url", defaultValue = "http://localhost:8703") baseUrl: String,
) {
    // Normalize once — trailing slash on AUTH_BASE_URL must not cause iss mismatch
    private val issuer = baseUrl.trimEnd('/')

    companion object {
        private val log: Logger = Logger.getLogger(JwtService::class.java)
    }

    data class Claims(
        val userId: String,
        val email: String,
        val appId: String?,
    )

    fun sign(userId: String, email: String, appId: String?, role: String? = null): String {
        val now = System.currentTimeMillis()
        val exp = now + expirySeconds * 1000L
        val builder = Jwts.builder()
            .header().keyId(ecKeyService.kid).and()
            .issuer(issuer)
            .subject(userId)
            .claim("userId", userId)
            .claim("email", email)
            .issuedAt(Date(now))
            .expiration(Date(exp))
        if (appId != null) {
            builder.claim("appId", appId)
            builder.audience().add(appId)
        }
        if (role != null) {
            // MP-JWT / Quarkus @RolesAllowed reads the `groups` claim as a list
            builder.claim("groups", listOf(role))
        }
        return builder.signWith(ecKeyService.privateKey).compact()
    }

    fun verify(token: String): Claims? {
        return try {
            val claims = Jwts.parser()
                .verifyWith(ecKeyService.publicKey)
                .requireIssuer(issuer)
                .build()
                .parseSignedClaims(token)
                .payload
            Claims(
                userId = claims["userId"] as? String ?: claims.subject ?: return null,
                email = claims["email"] as? String ?: return null,
                appId = claims["appId"] as? String,
            )
        } catch (e: JwtException) {
            log.debugf("JWT verification failed: %s", e.message)
            null
        }
    }
}
