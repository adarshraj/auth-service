package com.authservice.api

import com.authservice.api.dto.AuthResponse
import com.authservice.api.dto.LoginRequest
import com.authservice.api.dto.RegisterRequest
import com.authservice.api.dto.UserResponse
import com.authservice.security.CallerContext
import com.authservice.security.JwtFilter
import com.authservice.security.RateLimiter
import com.authservice.service.JwtService
import com.authservice.service.OAuthService
import com.authservice.service.UserService
import jakarta.inject.Inject
import jakarta.validation.Valid
import jakarta.ws.rs.BadRequestException
import jakarta.ws.rs.Consumes
import jakarta.ws.rs.DELETE
import jakarta.ws.rs.GET
import jakarta.ws.rs.HeaderParam
import jakarta.ws.rs.NotAuthorizedException
import jakarta.ws.rs.POST
import jakarta.ws.rs.Path
import jakarta.ws.rs.PathParam
import jakarta.ws.rs.Produces
import jakarta.ws.rs.QueryParam
import jakarta.ws.rs.container.ContainerRequestContext
import jakarta.ws.rs.core.Context
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import jakarta.ws.rs.core.UriInfo
import org.eclipse.microprofile.openapi.annotations.Operation
import org.eclipse.microprofile.openapi.annotations.tags.Tag
import org.jboss.logging.Logger
import java.net.URI
import java.security.SecureRandom

@Path("/auth")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
@Tag(name = "auth", description = "Authentication endpoints")
class AuthResource @Inject constructor(
    private val userService: UserService,
    private val jwtService: JwtService,
    private val oauthService: OAuthService,
    private val rateLimiter: RateLimiter,
) {
    companion object {
        private val log: Logger = Logger.getLogger(AuthResource::class.java)
        private val secureRandom = SecureRandom()
    }

    // ── Register ──────────────────────────────────────────────────────────────

    @POST
    @Path("/register")
    @Operation(summary = "Register a new user account")
    fun register(
        @Valid body: RegisterRequest,
        @HeaderParam("X-App-Id") appId: String?,
        @Context ctx: ContainerRequestContext,
    ): Response {
        checkRateLimit(ctx)
        val user = userService.register(
            email = body.email,
            password = body.password,
            name = body.name,
            appId = appId,
        )
        val token = jwtService.sign(user.id, user.email, appId)
        return Response.status(201).entity(AuthResponse(token, user.toResponse())).build()
    }

    // ── Login ─────────────────────────────────────────────────────────────────

    @POST
    @Path("/login")
    @Operation(summary = "Login with email and password; returns a JWT")
    fun login(
        @Valid body: LoginRequest,
        @HeaderParam("X-App-Id") appId: String?,
        @Context ctx: ContainerRequestContext,
    ): AuthResponse {
        checkRateLimit(ctx)
        val user = userService.login(body.email, body.password, appId)
        val token = jwtService.sign(user.id, user.email, appId)
        return AuthResponse(token, user.toResponse())
    }

    // ── Logout ────────────────────────────────────────────────────────────────

    @POST
    @Path("/logout")
    @Operation(summary = "Logout (stateless — client drops the token)")
    fun logout(): Response =
        Response.ok(mapOf("message" to "Logged out")).build()

    // ── Me ────────────────────────────────────────────────────────────────────

    @GET
    @Path("/me")
    @Operation(summary = "Get the current user (requires Bearer JWT)")
    fun me(@Context ctx: ContainerRequestContext): UserResponse {
        val caller = ctx.getProperty(JwtFilter.PROP_CALLER) as? CallerContext
            ?: throw NotAuthorizedException("Authentication required", "Bearer")
        return userService.getById(caller.userId).toResponse()
    }

    // ── Delete account ────────────────────────────────────────────────────────

    @DELETE
    @Path("/account")
    @Operation(summary = "Delete own account (requires Bearer JWT)")
    fun deleteAccount(@Context ctx: ContainerRequestContext): Response {
        val caller = ctx.getProperty(JwtFilter.PROP_CALLER) as? CallerContext
            ?: throw NotAuthorizedException("Authentication required", "Bearer")
        userService.deleteAccount(caller.userId)
        return Response.noContent().build()
    }

    // ── OAuth redirect ────────────────────────────────────────────────────────

    @GET
    @Path("/oauth/{provider}")
    @Operation(summary = "Redirect to OAuth provider (google or github)")
    fun oauthRedirect(
        @PathParam("provider") provider: String,
        @HeaderParam("X-App-Id") appId: String?,
    ): Response {
        val state = buildOAuthState(provider, appId)
        val url = when (provider) {
            "google" -> oauthService.googleAuthUrl(state)
            "github" -> oauthService.githubAuthUrl(state)
            else -> throw BadRequestException("Unsupported OAuth provider: $provider")
        }
        return Response.temporaryRedirect(URI.create(url)).build()
    }

    // ── OAuth callback ────────────────────────────────────────────────────────

    @GET
    @Path("/oauth/callback")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "OAuth callback — exchange code for JWT")
    fun oauthCallback(
        @QueryParam("provider") provider: String?,
        @QueryParam("code") code: String?,
        @QueryParam("state") state: String?,
        @QueryParam("error") error: String?,
    ): AuthResponse {
        if (error != null) throw BadRequestException("OAuth error: $error")
        if (code.isNullOrBlank()) throw BadRequestException("Missing OAuth code")

        val (resolvedProvider, appId) = parseOAuthState(state, provider)

        val oauthUser = when (resolvedProvider) {
            "google" -> oauthService.exchangeGoogleCode(code)
            "github" -> oauthService.exchangeGithubCode(code)
            else -> throw BadRequestException("Unsupported OAuth provider: $resolvedProvider")
        }

        val user = userService.findOrCreateByOAuth(
            provider = resolvedProvider,
            oauthId = oauthUser.id,
            email = oauthUser.email,
            name = oauthUser.name,
            avatarUrl = oauthUser.avatarUrl,
            appId = appId,
        )
        val token = jwtService.sign(user.id, user.email, appId)
        return AuthResponse(token, user.toResponse())
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private fun checkRateLimit(ctx: ContainerRequestContext) {
        val ip = ctx.getHeaderString("X-Forwarded-For")?.split(",")?.first()?.trim()
            ?: ctx.getHeaderString("X-Real-IP")
            ?: "unknown"
        if (!rateLimiter.tryAcquire("auth:ip:$ip")) {
            throw jakarta.ws.rs.WebApplicationException(
                Response.status(429)
                    .type(MediaType.APPLICATION_JSON)
                    .header("Retry-After", "60")
                    .entity(mapOf("error" to "too_many_requests", "message" to "Too many requests. Try again later.", "status" to 429))
                    .build()
            )
        }
    }

    /** Encode provider + appId into the OAuth state param. */
    private fun buildOAuthState(provider: String, appId: String?): String {
        val nonce = ByteArray(16).also { secureRandom.nextBytes(it) }
            .joinToString("") { "%02x".format(it) }
        return if (appId != null) "$provider:$appId:$nonce" else "$provider::$nonce"
    }

    /** Decode provider + appId from state; fall back to query param for provider. */
    private fun parseOAuthState(state: String?, fallbackProvider: String?): Pair<String, String?> {
        if (!state.isNullOrBlank()) {
            val parts = state.split(":")
            if (parts.size >= 2) {
                val p = parts[0].takeIf { it.isNotBlank() } ?: fallbackProvider ?: "google"
                val a = parts[1].takeIf { it.isNotBlank() }
                return p to a
            }
        }
        return (fallbackProvider ?: "google") to null
    }

    private fun UserService.UserView.toResponse() = UserResponse(
        id = id,
        email = email,
        name = name,
        emailVerified = emailVerified,
        avatarUrl = avatarUrl,
    )
}
