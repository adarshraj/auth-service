package com.authservice.security

import com.authservice.service.JwtService
import jakarta.annotation.Priority
import jakarta.inject.Inject
import jakarta.ws.rs.Priorities
import jakarta.ws.rs.container.ContainerRequestContext
import jakarta.ws.rs.container.ContainerRequestFilter
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import jakarta.ws.rs.ext.Provider
import org.jboss.logging.Logger

/**
 * Verifies Bearer JWT on endpoints that require an authenticated user:
 *   GET  /auth/me
 *   DELETE /auth/account
 *
 * All other /auth/ * endpoints are public (login, register, oauth, etc.).
 */
@Provider
@Priority(Priorities.AUTHENTICATION)
class JwtFilter @Inject constructor(
    private val jwtService: JwtService,
) : ContainerRequestFilter {

    companion object {
        private val log: Logger = Logger.getLogger(JwtFilter::class.java)
        const val PROP_CALLER = "auth.caller"

        // Paths that require a valid JWT
        private val PROTECTED = setOf("/auth/me", "/auth/account", "/auth/mfa/setup", "/auth/mfa/confirm", "/auth/mfa/disable")
    }

    override fun filter(ctx: ContainerRequestContext) {
        val path = ctx.uriInfo.path
        // Skip infra + admin + public auth endpoints
        if (path.startsWith("q/") || path.startsWith("/q/")) return
        if (path.startsWith("auth/apps") || path.startsWith("/auth/apps")) return

        val needsAuth = PROTECTED.any { path == it || path.startsWith("$it/") ||
            path == it.trimStart('/') || path.startsWith(it.trimStart('/') + "/") }
        if (!needsAuth) return

        val header = ctx.getHeaderString("Authorization")
        if (header.isNullOrBlank() || !header.startsWith("Bearer ")) {
            abort(ctx, "Missing or invalid Authorization header")
            return
        }

        val token = header.removePrefix("Bearer ").trim()
        val claims = jwtService.verify(token)
        if (claims == null) {
            log.debugf("Invalid JWT for path=%s", path)
            abort(ctx, "Invalid or expired token")
            return
        }

        ctx.setProperty(PROP_CALLER, CallerContext(
            userId = claims.userId,
            email = claims.email,
            appId = claims.appId,
        ))
    }

    private fun abort(ctx: ContainerRequestContext, message: String) {
        ctx.abortWith(
            Response.status(Response.Status.UNAUTHORIZED)
                .type(MediaType.APPLICATION_JSON)
                .entity(mapOf("error" to "unauthorized", "message" to message, "status" to 401))
                .build()
        )
    }
}
