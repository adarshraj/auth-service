package com.authservice.api

import com.authservice.api.dto.AuthResponse
import com.authservice.api.dto.LoginRequest
import com.authservice.api.dto.MfaChallengeResponse
import com.authservice.api.dto.MfaConfirmRequest
import com.authservice.api.dto.MfaDisableRequest
import com.authservice.api.dto.MfaSetupResponse
import com.authservice.api.dto.MfaVerifyRequest
import com.authservice.api.dto.RegisterRequest
import com.authservice.api.dto.UserResponse
import com.authservice.domain.AppRepository
import com.authservice.domain.OAuthCodeEntity
import com.authservice.domain.OAuthCodeRepository
import com.authservice.domain.RefreshTokenRepository
import com.authservice.security.CallerContext
import com.authservice.security.Hmac
import com.authservice.security.JwtFilter
import com.authservice.security.MfaNonceStore
import com.authservice.security.OAuthNonceStore
import com.authservice.security.RateLimiter
import com.authservice.service.JwtService
import com.authservice.service.OAuthService
import com.authservice.service.TotpService
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
import jakarta.ws.rs.core.UriBuilder
import org.eclipse.microprofile.config.inject.ConfigProperty
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
    private val refreshTokenRepository: RefreshTokenRepository,
    private val nonceStore: OAuthNonceStore,
    private val mfaNonceStore: MfaNonceStore,
    private val totpService: TotpService,
    // Purpose-specific secrets — each has its own env var to limit blast radius if one leaks
    @ConfigProperty(name = "auth.state-hmac-secret") private val stateHmacSecret: String,
    @ConfigProperty(name = "auth.token-pepper") private val tokenPepper: String,
    @ConfigProperty(name = "auth.mfa-hmac-secret") private val mfaHmacSecret: String,
) {
    companion object {
        private val log: Logger = Logger.getLogger(AuthResource::class.java)
        private val secureRandom = SecureRandom()
        private const val CODE_TTL_SECONDS = 60L
        // Stricter per-account limit to defend against distributed brute force from multiple IPs
        private const val PER_ACCOUNT_RPM = 10
        // MFA challenge tokens expire in 5 minutes
        private const val MFA_TOKEN_TTL_SECONDS = 300L
        // Per-userId rate limit for MFA verification — prevents brute force on 6-digit codes
        private const val MFA_VERIFY_RPM = 5
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
        val validatedAppId = userService.validateAppId(appId)
        val user = userService.register(
            email = body.email,
            password = body.password,
            name = body.name,
            appId = validatedAppId,
        )
        val role = validatedAppId?.let { userService.getRole(user.id, it) }
        val token = jwtService.sign(user.id, user.email, validatedAppId, role)
        val refreshToken = userService.issueRefreshToken(user.id, validatedAppId)
        return Response.status(201).entity(AuthResponse(token, refreshToken, user.toResponse())).build()
    }

    // ── Login ─────────────────────────────────────────────────────────────────

    @POST
    @Path("/login")
    @Operation(summary = "Login with email and password; returns a JWT or MFA challenge")
    fun login(
        @Valid body: LoginRequest,
        @HeaderParam("X-App-Id") appId: String?,
        @Context ctx: ContainerRequestContext,
    ): Response {
        checkRateLimit(ctx)
        val validatedAppId = userService.validateAppId(appId)
        // Per-account limit: catches distributed brute force that rotates IPs to bypass per-IP limit
        checkRateLimit("auth:account:${body.email.lowercase().trim()}", PER_ACCOUNT_RPM)
        val user = userService.login(body.email, body.password, validatedAppId)

        // If MFA is enabled, return a challenge instead of a JWT
        if (userService.isMfaEnabled(user.id)) {
            val mfaToken = buildMfaToken(user.id, user.email, validatedAppId)
            return Response.ok(MfaChallengeResponse(mfaToken = mfaToken)).build()
        }

        val role = validatedAppId?.let { userService.getRole(user.id, it) }
        val token = jwtService.sign(user.id, user.email, validatedAppId, role)
        val refreshToken = userService.issueRefreshToken(user.id, validatedAppId)
        return Response.ok(AuthResponse(token, refreshToken, user.toResponse())).build()
    }

    // ── MFA challenge exchange (OAuth redirect flow) ──────────────────────────

    @POST
    @Path("/mfa/challenge")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Operation(summary = "Exchange a one-time MFA code (from OAuth redirect) for an MFA challenge token")
    fun mfaChallengeExchange(
        @FormParam("code") @NotBlank code: String,
        @Context ctx: ContainerRequestContext,
    ): MfaChallengeResponse {
        checkRateLimit(ctx)
        // appId is bound to the token at creation time (in oauthCallback) — ignore client-supplied
        // X-App-Id to prevent an attacker from minting tokens for arbitrary apps
        val (userId, appId) = userService.consumeAuthToken(code, "mfa_challenge")
        val user = userService.getById(userId)
        val mfaToken = buildMfaToken(userId, user.email, appId)
        return MfaChallengeResponse(mfaToken = mfaToken)
    }

    // ── MFA verify (complete login after MFA challenge) ──────────────────────

    @POST
    @Path("/mfa/verify")
    @Operation(summary = "Complete login by verifying a TOTP code or backup code")
    fun mfaVerify(
        @Valid body: MfaVerifyRequest,
        @Context ctx: ContainerRequestContext,
    ): AuthResponse {
        checkRateLimit(ctx)
        val (userId, email, appId) = parseMfaToken(body.mfaToken)
        // Per-userId rate limit — prevents distributed brute force on 6-digit codes
        checkRateLimit("mfa:user:$userId", MFA_VERIFY_RPM)

        val secret = userService.getMfaSecret(userId)
            ?: throw BadRequestException("MFA not configured")

        val codeValid = totpService.verify(secret, body.code) ||
            userService.consumeBackupCode(userId, body.code)

        if (!codeValid) {
            log.infof("AUDIT mfa_verify_failed userId=%s", userId)
            throw NotAuthorizedException("Invalid MFA code", "Bearer")
        }

        log.infof("AUDIT mfa_verify_success userId=%s", userId)
        val role = appId?.let { userService.getRole(userId, it) }
        val token = jwtService.sign(userId, email, appId, role)
        val refreshToken = userService.issueRefreshToken(userId, appId)
        val user = userService.getById(userId)
        return AuthResponse(token, refreshToken, user.toResponse())
    }

    // ── MFA setup (authenticated users only) ─────────────────────────────────

    @POST
    @Path("/mfa/setup")
    @Operation(summary = "Start MFA enrollment — returns secret and QR URI")
    fun mfaSetup(@Context ctx: ContainerRequestContext): MfaSetupResponse {
        val caller = ctx.getProperty(JwtFilter.PROP_CALLER) as? CallerContext
            ?: throw NotAuthorizedException("Authentication required", "Bearer")
        val secret = totpService.generateSecret()
        val recoveryCodes = totpService.generateRecoveryCodes()
        userService.setupMfa(caller.userId, secret, recoveryCodes)
        val uri = totpService.buildOtpAuthUri(secret, caller.email)
        return MfaSetupResponse(secret = secret, otpauthUri = uri, recoveryCodes = recoveryCodes)
    }

    @POST
    @Path("/mfa/confirm")
    @Operation(summary = "Confirm MFA enrollment by verifying a TOTP code")
    fun mfaConfirm(
        @Valid body: MfaConfirmRequest,
        @Context ctx: ContainerRequestContext,
    ): Response {
        val caller = ctx.getProperty(JwtFilter.PROP_CALLER) as? CallerContext
            ?: throw NotAuthorizedException("Authentication required", "Bearer")
        checkRateLimit("mfa:user:${caller.userId}", MFA_VERIFY_RPM)
        val secret = userService.getMfaSecret(caller.userId)
            ?: throw BadRequestException("MFA setup not started")
        if (!totpService.verify(secret, body.code)) {
            throw BadRequestException("Invalid TOTP code — check your authenticator app and try again")
        }
        userService.confirmMfa(caller.userId)
        return Response.ok(mapOf("message" to "MFA enabled")).build()
    }

    @POST
    @Path("/mfa/disable")
    @Operation(summary = "Disable MFA (requires a valid TOTP or backup code)")
    fun mfaDisable(
        @Valid body: MfaDisableRequest,
        @Context ctx: ContainerRequestContext,
    ): Response {
        val caller = ctx.getProperty(JwtFilter.PROP_CALLER) as? CallerContext
            ?: throw NotAuthorizedException("Authentication required", "Bearer")
        val secret = userService.getMfaSecret(caller.userId)
            ?: throw BadRequestException("MFA is not configured for this account")
        if (!userService.isMfaEnabled(caller.userId)) {
            throw BadRequestException("MFA is not enabled")
        }
        val codeValid = totpService.verify(secret, body.code) ||
            userService.consumeBackupCode(caller.userId, body.code)
        if (!codeValid) {
            throw BadRequestException("Invalid code")
        }
        userService.disableMfa(caller.userId)
        return Response.ok(mapOf("message" to "MFA disabled")).build()
    }

    // ── Logout ────────────────────────────────────────────────────────────────

    @POST
    @Path("/logout")
    @Consumes(MediaType.WILDCARD)
    @Transactional
    @Operation(summary = "Logout — clears session cookie and optionally revokes a refresh token")
    fun logout(@QueryParam("refresh_token") refreshToken: String?): Response {
        if (!refreshToken.isNullOrBlank()) {
            // Revoke the refresh token so it cannot be used to obtain new access tokens
            val tokenHash = Hmac.sha256(refreshToken, tokenPepper)
            refreshTokenRepository.claimToken(tokenHash) // returns null if already revoked/expired — no error
        }
        return Response.ok(mapOf("message" to "Logged out")).build()
    }

    // ── Refresh ───────────────────────────────────────────────────────────────

    @POST
    @Path("/refresh")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Transactional
    @Operation(summary = "Exchange a refresh token for a new access token + refresh token (rotation)")
    fun refresh(
        @FormParam("refresh_token") @NotBlank refreshToken: String,
        @Context ctx: ContainerRequestContext,
    ): AuthResponse {
        checkRateLimit(ctx)
        val (userId, appId, newRefreshToken) = userService.rotateRefreshToken(refreshToken)
        val user = userService.getById(userId)
        val role = appId?.let { userService.getRole(userId, it) }
        val token = jwtService.sign(userId, user.email, appId, role)
        log.infof("AUDIT token_refreshed userId=%s app=%s", userId, appId ?: "none")
        return AuthResponse(token, newRefreshToken, user.toResponse())
    }

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
        val validatedAppId = userService.validateAppId(appId)
        if (redirectUri != null) {
            validateRedirectUri(redirectUri, validatedAppId)
        }
        val state = buildOAuthState(provider, validatedAppId, redirectUri)
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
            emailVerified = oauthUser.emailVerified,
        )

        // If user has MFA enabled, require a second factor before issuing a JWT
        if (userService.isMfaEnabled(user.id)) {
            return if (redirectUri != null) {
                // Issue an opaque single-use code that the client exchanges for the mfaToken
                // via POST /auth/mfa/challenge. This avoids exposing the mfaToken in the URL
                // (browser history, Referer headers, proxy logs).
                val mfaCode = userService.createAuthToken(user.id, "mfa_challenge", expiresInHours = 0, expiresInSeconds = CODE_TTL_SECONDS, appId = appId)
                val location = UriBuilder.fromUri(redirectUri)
                    .queryParam("mfa_required", "true")
                    .queryParam("mfa_code", mfaCode)
                    .build()
                Response.temporaryRedirect(location).build()
            } else {
                val mfaToken = buildMfaToken(user.id, user.email, appId)
                Response.ok(MfaChallengeResponse(mfaToken = mfaToken)).build()
            }
        }

        return if (redirectUri != null) {
            val authCode = issueOAuthCode(user.id, user.email, appId)
            // UriBuilder handles existing query params (appends & when needed) and percent-encodes values
            val location = UriBuilder.fromUri(redirectUri).queryParam("code", authCode).build()
            Response.temporaryRedirect(location).build()
        } else {
            val role = appId?.let { userService.getRole(user.id, it) }
            val token = jwtService.sign(user.id, user.email, appId, role)
            val refreshToken = userService.issueRefreshToken(user.id, appId)
            Response.ok(AuthResponse(token, refreshToken, user.toResponse())).build()
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
    ): Response {
        checkRateLimit(ctx)
        // claimCode atomically marks the code used via UPDATE-before-SELECT,
        // eliminating the TOCTOU race where two concurrent requests could both
        // exchange the same one-time code before either marked it used.
        val entity = oauthCodeRepository.claimCode(Hmac.sha256(code, tokenPepper))
            ?: throw BadRequestException("Invalid or expired auth code")
        val user = try { userService.getById(entity.userId) }
            catch (e: jakarta.ws.rs.NotFoundException) { throw BadRequestException("Invalid auth code") }

        // If MFA is enabled, return a challenge instead of a JWT
        if (userService.isMfaEnabled(entity.userId)) {
            val mfaToken = buildMfaToken(entity.userId, entity.email, entity.appId)
            return Response.ok(MfaChallengeResponse(mfaToken = mfaToken)).build()
        }

        val role = entity.appId?.let { userService.getRole(entity.userId, it) }
        val token = jwtService.sign(entity.userId, entity.email, entity.appId, role)
        val refreshToken = userService.issueRefreshToken(entity.userId, entity.appId)
        log.infof("AUDIT token_exchanged userId=%s app=%s", entity.userId, entity.appId ?: "none")
        return Response.ok(AuthResponse(token, refreshToken, user.toResponse())).build()
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /**
     * Build a short-lived, single-use HMAC-signed MFA challenge token.
     * Format: base64url(userId\nemail\nappId\nnonce\nexpiry)~hmac
     * Uses auth.mfa-hmac-secret (separate from OAuth state and token pepper).
     * The nonce is registered in MfaNonceStore so the token can only be used once.
     */
    private fun buildMfaToken(userId: String, email: String, appId: String?): String {
        val nonce = ByteArray(16).also { secureRandom.nextBytes(it) }
            .joinToString("") { "%02x".format(it) }
        mfaNonceStore.register(nonce)
        val expiry = (System.currentTimeMillis() / 1000) + MFA_TOKEN_TTL_SECONDS
        val parts = listOf(userId, email, appId ?: "", nonce, expiry.toString())
        val payload = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString(parts.joinToString("\n").toByteArray())
        val sig = Hmac.sha256(payload, mfaHmacSecret)
        return "$payload~$sig"
    }

    /** Parse, verify, and consume an MFA challenge token (single-use). Returns (userId, email, appId?). */
    private fun parseMfaToken(token: String): Triple<String, String, String?> {
        val tildeIdx = token.lastIndexOf('~')
        if (tildeIdx < 0) throw BadRequestException("Invalid MFA token")
        val payload = token.substring(0, tildeIdx)
        val sig = token.substring(tildeIdx + 1)
        if (!Hmac.verify(payload, sig, mfaHmacSecret)) throw BadRequestException("Invalid MFA token")
        return try {
            val decoded = String(java.util.Base64.getUrlDecoder().decode(payload))
            val parts = decoded.split("\n")
            if (parts.size < 5) throw BadRequestException("Invalid MFA token")
            val nonce = parts[3]
            if (!mfaNonceStore.consume(nonce)) throw BadRequestException("MFA token already used or expired — please login again")
            val expiry = parts[4].toLongOrNull() ?: throw BadRequestException("Invalid MFA token")
            if (System.currentTimeMillis() / 1000 > expiry) throw BadRequestException("MFA token expired — please login again")
            Triple(parts[0], parts[1], parts[2].takeIf { it.isNotBlank() })
        } catch (e: IllegalArgumentException) {
            throw BadRequestException("Invalid MFA token")
        }
    }

    private fun issueOAuthCode(userId: String, email: String, appId: String?): String {
        val rawCode = ByteArray(32).also { secureRandom.nextBytes(it) }
            .joinToString("") { "%02x".format(it) }
        // Store HMAC of the code — a DB dump cannot be used to redeem outstanding codes
        oauthCodeRepository.persist(OAuthCodeEntity().apply {
            id = UUID.randomUUID().toString()
            this.code = Hmac.sha256(rawCode, tokenPepper)
            this.userId = userId
            this.email = email
            this.appId = appId
            expiresAt = Instant.now().plusSeconds(CODE_TTL_SECONDS)
            used = false
            createdAt = Instant.now()
        })
        return rawCode
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

    /** Encode provider + appId + redirectUri into a signed OAuth state param.
     *  Format: base64url(provider\nappId\nnonce[\nredirectUri])~hmac
     *  Uses auth.state-hmac-secret (separate from admin key and token pepper).
     *  The nonce is registered in OAuthNonceStore so it can only be consumed once
     *  at callback time — preventing CSRF and state-replay attacks. */
    private fun buildOAuthState(provider: String, appId: String?, redirectUri: String?): String {
        val nonce = ByteArray(16).also { secureRandom.nextBytes(it) }
            .joinToString("") { "%02x".format(it) }
        nonceStore.register(nonce)
        val parts = listOfNotNull(provider, appId ?: "", nonce, redirectUri)
        val payload = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString(parts.joinToString("\n").toByteArray())
        val sig = Hmac.sha256(payload, stateHmacSecret)
        return "$payload~$sig"
    }

    /** Decode and verify a signed OAuth state param. Rejects missing, tampered, replayed, or malformed state. */
    private fun parseOAuthState(state: String?): Triple<String, String?, String?> {
        if (state.isNullOrBlank()) throw BadRequestException("Missing OAuth state parameter")
        val tildeIdx = state.lastIndexOf('~')
        if (tildeIdx < 0) throw BadRequestException("Invalid OAuth state parameter")

        val payload = state.substring(0, tildeIdx)
        val sig = state.substring(tildeIdx + 1)
        if (!Hmac.verify(payload, sig, stateHmacSecret)) throw BadRequestException("Invalid OAuth state signature")

        return try {
            val decoded = String(java.util.Base64.getUrlDecoder().decode(payload))
            val parts = decoded.split("\n")
            if (parts.size < 3) throw BadRequestException("Invalid OAuth state parameter")
            val provider = parts[0].takeIf { it.isNotBlank() }
                ?: throw BadRequestException("Invalid OAuth state parameter")
            val appId = parts[1].takeIf { it.isNotBlank() }
            val nonce = parts[2]
            // Consume the nonce — rejects replayed state params even if signature is valid
            if (!nonceStore.consume(nonce)) throw BadRequestException("OAuth state expired or already used — restart the login flow")
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
        // Normalize both sides before comparing: lowercase scheme+host, strip trailing slash,
        // strip default ports (443 for https, 80 for http) to prevent bypass via port variation.
        val normalizedRequest = normalizeRedirectUri(uri)
        if (allowed.none { runCatching { normalizeRedirectUri(URI.create(it)) }.getOrNull() == normalizedRequest }) {
            throw BadRequestException("redirect_uri is not registered for app '$appId'")
        }
    }

    /**
     * Normalize a redirect URI for comparison:
     * - Lowercase scheme and host
     * - Strip default ports (443 for https, 80 for http)
     * - Strip trailing slash from path
     */
    private fun normalizeRedirectUri(uri: URI): String {
        val scheme = uri.scheme.lowercase()
        val host = uri.host.lowercase()
        val port = when {
            uri.port == -1 -> ""
            scheme == "https" && uri.port == 443 -> ""
            scheme == "http" && uri.port == 80 -> ""
            else -> ":${uri.port}"
        }
        val path = (uri.path ?: "").trimEnd('/')
        return "$scheme://$host$port$path"
    }

    private fun UserService.UserView.toResponse() = UserResponse(
        id = id,
        email = email,
        name = name,
        emailVerified = emailVerified,
        avatarUrl = avatarUrl,
    )
}
