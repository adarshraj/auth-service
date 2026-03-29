package com.authservice.api

import com.authservice.api.dto.AuthResponse
import com.authservice.api.dto.LoginRequest
import com.authservice.api.dto.RegisterRequest
import com.authservice.api.dto.UserResponse
import com.authservice.domain.AppRepository
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
    private val appRepository: AppRepository,
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
        @QueryParam("redirect_uri") redirectUri: String?,
    ): Response {
        if (redirectUri != null) {
            validateRedirectUri(redirectUri, appId)
        }
        val state = buildOAuthState(provider, appId, redirectUri)
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
    @Operation(summary = "OAuth callback — exchange code for JWT; redirects to redirect_uri if present in state")
    fun oauthCallback(
        @QueryParam("provider") provider: String?,
        @QueryParam("code") code: String?,
        @QueryParam("state") state: String?,
        @QueryParam("error") error: String?,
    ): Response {
        if (error != null) throw BadRequestException("OAuth error: $error")
        if (code.isNullOrBlank()) throw BadRequestException("Missing OAuth code")

        val (resolvedProvider, appId, redirectUri) = parseOAuthState(state, provider)

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

        return if (redirectUri != null) {
            val location = URI.create("$redirectUri#token=$token")
            Response.temporaryRedirect(location).build()
        } else {
            Response.ok(AuthResponse(token, user.toResponse())).build()
        }
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

    /** Encode provider + appId + redirectUri into the OAuth state param.
     *  Format: base64(provider\nappId\nnonce[\nredirectUri])
     *  Using newline as delimiter inside base64 avoids collision with URL-special chars in redirectUri. */
    private fun buildOAuthState(provider: String, appId: String?, redirectUri: String?): String {
        val nonce = ByteArray(16).also { secureRandom.nextBytes(it) }
            .joinToString("") { "%02x".format(it) }
        val parts = listOfNotNull(provider, appId ?: "", nonce, redirectUri)
        return java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString(parts.joinToString("\n").toByteArray())
    }

    /** Decode provider + appId + redirectUri from state; fall back to query param for provider. */
    private fun parseOAuthState(state: String?, fallbackProvider: String?): Triple<String, String?, String?> {
        if (!state.isNullOrBlank()) {
            try {
                val decoded = String(java.util.Base64.getUrlDecoder().decode(state))
                val parts = decoded.split("\n")
                if (parts.size >= 3) {
                    val p = parts[0].takeIf { it.isNotBlank() } ?: fallbackProvider ?: "google"
                    val a = parts[1].takeIf { it.isNotBlank() }
                    val r = parts.getOrNull(3)?.takeIf { it.isNotBlank() }
                    return Triple(p, a, r)
                }
            } catch (_: Exception) {
                // fall through to legacy format
            }
            // legacy plain-text state: "provider:appId:nonce"
            val parts = state.split(":")
            if (parts.size >= 2) {
                val p = parts[0].takeIf { it.isNotBlank() } ?: fallbackProvider ?: "google"
                val a = parts[1].takeIf { it.isNotBlank() }
                return Triple(p, a, null)
            }
        }
        return Triple(fallbackProvider ?: "google", null, null)
    }

    /** Validate that the given redirect URI is registered for the app. */
    private fun validateRedirectUri(redirectUri: String, appId: String?) {
        if (appId == null) throw BadRequestException("redirect_uri requires X-App-Id")
        val app = appRepository.findById(appId)
            ?: throw BadRequestException("Unknown app: $appId")
        val allowed = app.allowedRedirectUris()
        if (allowed.isEmpty()) throw BadRequestException("App '$appId' has no redirect URIs registered")
        if (redirectUri !in allowed) throw BadRequestException("redirect_uri is not registered for app '$appId'")
    }

    private fun UserService.UserView.toResponse() = UserResponse(
        id = id,
        email = email,
        name = name,
        emailVerified = emailVerified,
        avatarUrl = avatarUrl,
    )
}
