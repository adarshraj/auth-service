package com.authservice.service

import io.jsonwebtoken.JwtException
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.Keys
import jakarta.enterprise.context.ApplicationScoped
import org.eclipse.microprofile.config.inject.ConfigProperty
import org.jboss.logging.Logger
import java.nio.charset.StandardCharsets
import java.util.Date

/**
 * JWT sign/verify using HS256. Token payload matches finance-tracker's format:
 *   { sub, userId, email, appId, iat, exp }
 *
 * The `sub` field is set to userId so ai-wrap (and any other service sharing JWT_SECRET)
 * can identify the caller without knowing about finance-tracker's custom `userId` field.
 */
@ApplicationScoped
class JwtService(
    @ConfigProperty(name = "auth.jwt.secret") private val jwtSecret: String,
    @ConfigProperty(name = "auth.jwt.expiry-seconds", defaultValue = "604800") private val expirySeconds: Long,
) {
    companion object {
        private val log: Logger = Logger.getLogger(JwtService::class.java)
    }

    private val signingKey by lazy {
        Keys.hmacShaKeyFor(jwtSecret.toByteArray(StandardCharsets.UTF_8))
    }

    data class Claims(
        val userId: String,
        val email: String,
        val appId: String?,
    )

    fun sign(userId: String, email: String, appId: String?): String {
        val now = System.currentTimeMillis()
        val exp = now + expirySeconds * 1000L
        val builder = Jwts.builder()
            .subject(userId)
            .claim("userId", userId)
            .claim("email", email)
            .issuedAt(Date(now))
            .expiration(Date(exp))
        if (appId != null) builder.claim("appId", appId)
        return builder.signWith(signingKey).compact()
    }

    fun verify(token: String): Claims? {
        return try {
            val claims = Jwts.parser()
                .verifyWith(signingKey)
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
