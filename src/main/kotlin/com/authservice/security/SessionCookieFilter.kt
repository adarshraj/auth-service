package com.authservice.security

import com.authservice.api.VerifyResource
import jakarta.annotation.Priority
import jakarta.ws.rs.Priorities
import jakarta.ws.rs.container.ContainerRequestContext
import jakarta.ws.rs.container.ContainerResponseContext
import jakarta.ws.rs.container.ContainerResponseFilter
import jakarta.ws.rs.core.NewCookie
import jakarta.ws.rs.ext.Provider
import org.eclipse.microprofile.config.inject.ConfigProperty
import java.util.Date

/**
 * Sets a `platform_session` cookie on successful auth responses.
 *
 * Intercepts responses from /auth/login, /auth/register, /auth/refresh, /auth/token
 * that return a 2xx status with a JSON body containing a "token" field.
 * Sets the JWT as an HttpOnly, Secure, SameSite=Lax cookie on the configured domain
 * so that browser requests to any *.homelab.local admin UI carry the session automatically.
 *
 * Also handles /auth/logout by clearing the cookie.
 */
@Provider
@Priority(Priorities.HEADER_DECORATOR)
class SessionCookieFilter(
    @ConfigProperty(name = "auth.session.cookie-domain", defaultValue = "") private val cookieDomain: String,
    @ConfigProperty(name = "auth.jwt.expiry-seconds", defaultValue = "900") private val jwtExpirySeconds: Long,
) : ContainerResponseFilter {

    companion object {
        private val TOKEN_PATHS = setOf(
            "auth/login", "/auth/login",
            "auth/register", "/auth/register",
            "auth/refresh", "/auth/refresh",
            "auth/token", "/auth/token",
        )
        private val LOGOUT_PATHS = setOf("auth/logout", "/auth/logout")
    }

    override fun filter(request: ContainerRequestContext, response: ContainerResponseContext) {
        val path = request.uriInfo.path

        // Clear cookie on logout
        if (LOGOUT_PATHS.any { path == it }) {
            response.headers.add("Set-Cookie", buildClearCookie())
            return
        }

        // Only process successful auth responses
        if (response.status !in 200..201) return
        if (TOKEN_PATHS.none { path == it }) return

        val entity = response.entity
        if (entity == null) return

        // Extract token from the response body (AuthResponse has a "token" field)
        val token = extractToken(entity) ?: return

        val domain = cookieDomain.takeIf { it.isNotBlank() }
        val maxAge = jwtExpirySeconds.toInt()

        val cookie = NewCookie.Builder(VerifyResource.SESSION_COOKIE)
            .value(token)
            .path("/")
            .maxAge(maxAge)
            .httpOnly(true)
            .secure(true)
            .also { if (domain != null) it.domain(domain) }
            .sameSite(NewCookie.SameSite.LAX)
            .build()

        response.headers.add("Set-Cookie", cookie)
    }

    private fun buildClearCookie(): String {
        val domain = cookieDomain.takeIf { it.isNotBlank() }
        val sb = StringBuilder("${VerifyResource.SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax")
        if (domain != null) sb.append("; Domain=$domain")
        return sb.toString()
    }

    @Suppress("UNCHECKED_CAST")
    private fun extractToken(entity: Any): String? {
        // AuthResponse is a data class — access via reflection or map
        return try {
            val field = entity::class.java.getDeclaredField("token")
            field.isAccessible = true
            field.get(entity) as? String
        } catch (_: Exception) {
            // If it's a map (unlikely but safe)
            (entity as? Map<String, Any>)?.get("token") as? String
        }
    }
}
