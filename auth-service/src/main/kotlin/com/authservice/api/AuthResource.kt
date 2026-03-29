package com.authservice.api

import com.authservice.api.dto.AuthResponse
import com.authservice.api.dto.LoginRequest
import com.authservice.api.dto.RegisterRequest
import com.authservice.api.dto.UserResponse
import com.authservice.domain.AppRepository
import com.authservice.domain.OAuthCodeEntity
import com.authservice.domain.OAuthCodeRepository
import com.authservice.security.CallerContext
import com.authservice.security.JwtFilter
import com.authservice.security.RateLimiter
import com.authservice.service.JwtService
import com.authservice.service.OAuthService
import com.authservice.service.UserService
import jakarta.inject.Inject
import jakarta.transaction.Transactional
import jakarta.validation.Valid
import jakarta.validation.constraints.NotBlank
import jakarta.ws.rs.BadRequestException
import jakarta.ws.rs.Consumes
import jakarta.ws.rs.DELETE
import jakarta.ws.rs.FormParam
import jakarta.ws.rs.GET
import jakarta.ws.rs.HeaderParam
import jakarta.ws.rs.NotAuthorizedException
import jakarta.ws.rs.POST
import jakarta.ws.rs.Path
import jakarta.ws.rs.PathParam
import jakarta.ws.rs.Produces
import jakarta.ws.rs.QueryParam
import jakarta.ws.rs.WebApplicationException
import jakarta.ws.rs.container.ContainerRequestContext
import jakarta.ws.rs.core.Context
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import org.eclipse.microprofile.openapi.annotations.Operation
import org.eclipse.microprofile.openapi.annotations.tags.Tag
import org.jboss.logging.Logger
import java.net.URI
import java.security.SecureRandom
import java.time.Instant
import java.util.UUID

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
    private val oauthCodeRepository: OAuthCodeRepository,
) {
    companion object {
        private val log: Logger = Logger.getLogger(AuthResource::class.java)
        private val secureRandom = SecureRandom()
        private const val CODE_TTL_SECONDS = 60L
        // Stricter per-account limit to defend against distributed brute force from multiple IPs
        private const val PER_ACCOUNT_RPM = 10
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
        // Per-account limit: catches distributed brute force that rotates IPs to bypass per-IP limit
        checkRateLimit("auth:account:${body.email.lowercase().trim()}", PER_ACCOUNT_RPM)
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
    @Transactional
    @Operation(summary = "OAuth callback — issues a short-lived code; redirects to redirect_uri?code= if present, else returns JSON")
    fun oauthCallback(
        @QueryParam("provider") provider: String?,
        @QueryParam("code") code: String?,
        @QueryParam("state") state: String?,
        @QueryParam("error") error: String?,
    ): Response {
        if (error != null) throw BadRequestException("OAuth error: $error")
        if (code.isNullOrBlank()) throw BadRequestException("Missing OAuth code")

        // State is mandatory — it encodes the provider and protects against CSRF
        val (resolvedProvider, appId, redirectUri) = parseOAuthState(state)

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

        return if (redirectUri != null) {
            val authCode = issueOAuthCode(user.id, user.email, appId)
            val location = URI.create("$redirectUri?code=$authCode")
            Response.temporaryRedirect(location).build()
        } else {
            val token = jwtService.sign(user.id, user.email, appId)
            Response.ok(AuthResponse(token, user.toResponse())).build()
        }
    }

    // ── Token exchange ────────────────────────────────────────────────────────

    @POST
    @Path("/token")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Transactional
    @Operation(summary = "Exchange a one-time OAuth code for a JWT (code valid for 60 seconds)")
    fun exchangeToken(
        @FormParam("code") @NotBlank code: String,
        @Context ctx: ContainerRequestContext,
    ): AuthResponse {
        checkRateLimit(ctx)
        val entity = oauthCodeRepository.findByCode(code)
            ?: throw BadRequestException("Invalid auth code")
        if (entity.used) throw BadRequestException("Auth code already used")
        if (Instant.now().isAfter(entity.expiresAt)) throw BadRequestException("Auth code expired")
        entity.used = true

        val token = jwtService.sign(entity.userId, entity.email, entity.appId)
        val user = userService.getById(entity.userId)
        return AuthResponse(token, user.toResponse())
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private fun issueOAuthCode(userId: String, email: String, appId: String?): String {
        val code = ByteArray(32).also { secureRandom.nextBytes(it) }
            .joinToString("") { "%02x".format(it) }
        oauthCodeRepository.persist(OAuthCodeEntity().apply {
            id = UUID.randomUUID().toString()
            this.code = code
            this.userId = userId
            this.email = email
            this.appId = appId
            expiresAt = Instant.now().plusSeconds(CODE_TTL_SECONDS)
            used = false
            createdAt = Instant.now()
        })
        return code
    }

    private fun checkRateLimit(ctx: ContainerRequestContext) {
        // Take the rightmost (trusted proxy-set) IP from X-Forwarded-For to prevent spoofing
        val ip = ctx.getHeaderString("X-Forwarded-For")
            ?.split(",")?.last()?.trim()
            ?: ctx.getHeaderString("X-Real-IP")
            ?: "unknown"
        checkRateLimit("auth:ip:$ip", rateLimiter.configuredRpm())
    }

    private fun checkRateLimit(key: String, maxRequests: Int) {
        if (!rateLimiter.tryAcquire(key, maxRequests)) {
            throw WebApplicationException(
                Response.status(429)
                    .type(MediaType.APPLICATION_JSON)
                    .header("Retry-After", "60")
                    .entity(mapOf("error" to "too_many_requests", "message" to "Too many requests. Try again later.", "status" to 429))
                    .build()
            )
        }
    }

    /** Encode provider + appId + redirectUri into the OAuth state param.
     *  Format: base64url(provider\nappId\nnonce[\nredirectUri]) */
    private fun buildOAuthState(provider: String, appId: String?, redirectUri: String?): String {
        val nonce = ByteArray(16).also { secureRandom.nextBytes(it) }
            .joinToString("") { "%02x".format(it) }
        val parts = listOfNotNull(provider, appId ?: "", nonce, redirectUri)
        return java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString(parts.joinToString("\n").toByteArray())
    }

    /** Decode provider + appId + redirectUri from state.
     *  State is mandatory — absence or invalid format is rejected to prevent CSRF. */
    private fun parseOAuthState(state: String?): Triple<String, String?, String?> {
        if (state.isNullOrBlank()) throw BadRequestException("Missing OAuth state parameter")
        return try {
            val decoded = String(java.util.Base64.getUrlDecoder().decode(state))
            val parts = decoded.split("\n")
            if (parts.size < 3) throw BadRequestException("Invalid OAuth state parameter")
            val provider = parts[0].takeIf { it.isNotBlank() }
                ?: throw BadRequestException("Invalid OAuth state parameter")
            val appId = parts[1].takeIf { it.isNotBlank() }
            val redirectUri = parts.getOrNull(3)?.takeIf { it.isNotBlank() }
            Triple(provider, appId, redirectUri)
        } catch (e: IllegalArgumentException) {
            throw BadRequestException("Invalid OAuth state parameter")
        }
    }

    /** Validate that the redirect URI is HTTPS (HTTP allowed for localhost only) and registered for the app. */
    private fun validateRedirectUri(redirectUri: String, appId: String?) {
        val uri = try { URI.create(redirectUri) } catch (e: Exception) {
            throw BadRequestException("Invalid redirect_uri format")
        }
        val scheme = uri.scheme?.lowercase()
        val host = uri.host?.lowercase() ?: ""
        val isLocalhost = host == "localhost" || host == "127.0.0.1"
        if (scheme != "https" && !(scheme == "http" && isLocalhost)) {
            throw BadRequestException("redirect_uri must use HTTPS (HTTP only allowed for localhost)")
        }

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
