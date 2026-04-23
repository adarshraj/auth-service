package com.authservice.api

import com.authservice.service.JwtService
import jakarta.inject.Inject
import jakarta.ws.rs.Consumes
import jakarta.ws.rs.CookieParam
import jakarta.ws.rs.GET
import jakarta.ws.rs.HeaderParam
import jakarta.ws.rs.Path
import jakarta.ws.rs.Produces
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import org.eclipse.microprofile.openapi.annotations.Operation
import org.eclipse.microprofile.openapi.annotations.tags.Tag
import org.jboss.logging.Logger

/**
 * Traefik ForwardAuth endpoint.
 *
 * Traefik sends the original request's headers (including cookies) to this endpoint.
 * Returns 200 if the user has a valid session, 401 otherwise.
 * On 401, sets X-Auth-Redirect so the error page / Traefik middleware can redirect to login.
 *
 * Accepts auth via:
 *   1. `platform_session` cookie (browser access to admin UIs)
 *   2. `Authorization: Bearer <token>` header (API access)
 */
@Path("/auth")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
@Tag(name = "auth", description = "Authentication endpoints")
class VerifyResource @Inject constructor(
    private val jwtService: JwtService,
) {
    companion object {
        private val log: Logger = Logger.getLogger(VerifyResource::class.java)
        const val SESSION_COOKIE = "platform_session"
    }

    @GET
    @Path("/verify")
    @Operation(summary = "Verify session for Traefik ForwardAuth — returns 200 or 401")
    fun verify(
        @CookieParam(SESSION_COOKIE) sessionCookie: String?,
        @HeaderParam("Authorization") authHeader: String?,
    ): Response {
        // Try cookie first (browser), then Bearer header (API)
        val token = sessionCookie
            ?: authHeader?.removePrefix("Bearer ")?.trim()?.takeIf { authHeader.startsWith("Bearer ") }

        if (token.isNullOrBlank()) {
            return unauthorized()
        }

        val claims = jwtService.verify(token)
        if (claims == null) {
            return unauthorized()
        }

        // Forward user identity to downstream services via headers
        return Response.ok()
            .header("X-Auth-User-Id", claims.userId)
            .header("X-Auth-User-Email", claims.email)
            .build()
    }

    private fun unauthorized(): Response =
        Response.status(Response.Status.UNAUTHORIZED)
            .header("X-Auth-Redirect", "true")
            .entity(mapOf("error" to "unauthorized", "message" to "Authentication required", "status" to 401))
            .build()
}
