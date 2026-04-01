package com.authservice.service

import com.authservice.domain.AppRepository
import com.authservice.domain.AuthTokenEntity
import com.authservice.domain.AuthTokenRepository
import com.authservice.domain.RefreshTokenEntity
import com.authservice.domain.RefreshTokenRepository
import com.authservice.domain.UserAppAccessEntity
import com.authservice.domain.UserAppAccessId
import com.authservice.domain.UserAppAccessRepository
import com.authservice.domain.UserEntity
import com.authservice.domain.UserRepository
import com.authservice.security.Hmac
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import jakarta.transaction.Transactional
import jakarta.ws.rs.BadRequestException
import jakarta.ws.rs.ForbiddenException
import jakarta.ws.rs.NotFoundException
import jakarta.ws.rs.NotAuthorizedException
import jakarta.ws.rs.WebApplicationException
import jakarta.ws.rs.core.Response
import org.eclipse.microprofile.config.inject.ConfigProperty
import org.jboss.logging.Logger
import java.security.SecureRandom
import java.time.Instant
import java.time.temporal.ChronoUnit

@ApplicationScoped
class UserService @Inject constructor(
    private val userRepository: UserRepository,
    private val appRepository: AppRepository,
    private val accessRepository: UserAppAccessRepository,
    private val authTokenRepository: AuthTokenRepository,
    private val refreshTokenRepository: RefreshTokenRepository,
    private val passwordService: PasswordService,
    @ConfigProperty(name = "auth.token-pepper") private val tokenPepper: String,
    @ConfigProperty(name = "auth.refresh-token.expiry-seconds", defaultValue = "604800") private val refreshTokenExpirySeconds: Long,
) {
    companion object {
        private val log: Logger = Logger.getLogger(UserService::class.java)
        private val secureRandom = SecureRandom()
    }

    data class UserView(
        val id: String,
        val email: String,
        val name: String?,
        val emailVerified: Boolean,
        val avatarUrl: String?,
    )

    // ── Registration ──────────────────────────────────────────────────────────

    @Transactional
    fun register(email: String, password: String?, name: String?, appId: String?): UserView {
        if (password == null) {
            throw BadRequestException("Password is required")
        }
        if (passwordService.isCommon(password)) {
            throw BadRequestException("This password is too common — please choose a stronger one")
        }
        val normalizedEmail = email.lowercase().trim()
        if (userRepository.findByEmail(normalizedEmail) != null) {
            // Perform a dummy hash to equalize timing — prevents email enumeration via response time
            passwordService.dummyHash()
            // Generic message — do not reveal whether the email is registered (prevents enumeration)
            throw BadRequestException("Registration failed — check your details and try again")
        }
        val user = UserEntity().apply {
            id = generateId()
            this.email = normalizedEmail
            this.name = name ?: normalizedEmail.substringBefore('@')
            this.passwordHash = password?.let { passwordService.hash(it) }
            this.emailVerified = false
            this.createdAt = Instant.now()
            this.updatedAt = Instant.now()
        }
        userRepository.persist(user)
        log.infof("Registered user id=%s email=%s", user.id, user.email)

        if (appId != null) {
            val app = appRepository.findById(appId)
            if (app != null && app.requiresExplicitAccess) {
                grantAccessInternal(user.id, appId, "user")
            }
        }

        return user.toView()
    }

    // ── Login ─────────────────────────────────────────────────────────────────

    @Transactional
    fun login(email: String, password: String, appId: String?): UserView {
        val normalizedEmail = email.lowercase().trim()
        val user = userRepository.findByEmail(normalizedEmail)
            ?: run {
                // Dummy verify to equalize timing — without this, unknown-email responses are
                // measurably faster (no bcrypt), revealing whether the email is registered.
                passwordService.dummyVerify(password)
                log.infof("AUDIT login_failed reason=unknown_email email=%s app=%s", normalizedEmail, appId ?: "none")
                throw NotAuthorizedException("Invalid email or password", "Bearer")
            }

        if (user.passwordHash == null) {
            // Dummy verify to equalize timing with the has-password path
            passwordService.dummyVerify(password)
            // Generic message — do not reveal that this email is registered via OAuth only (account enumeration)
            log.infof("AUDIT login_failed reason=no_password userId=%s app=%s", user.id, appId ?: "none")
            throw NotAuthorizedException("Invalid email or password", "Bearer")
        }

        if (!passwordService.verify(password, user.passwordHash!!)) {
            log.infof("AUDIT login_failed reason=bad_password userId=%s app=%s", user.id, appId ?: "none")
            throw NotAuthorizedException("Invalid email or password", "Bearer")
        }

        checkAppAccess(user, appId)
        log.infof("AUDIT login_success userId=%s app=%s", user.id, appId ?: "none")
        return user.toView()
    }

    // ── OAuth find-or-create ──────────────────────────────────────────────────

    @Transactional
    fun findOrCreateByOAuth(
        provider: String,
        oauthId: String,
        email: String,
        name: String,
        avatarUrl: String?,
        appId: String?,
        emailVerified: Boolean,
    ): UserView {
        // Match by OAuth identity first
        var user = userRepository.findByOAuth(provider, oauthId)

        if (user == null) {
            // Do NOT auto-link by email — this is an account takeover vector.
            // If an attacker controls an OAuth account with the victim's email they would
            // silently gain access to the existing password account.
            // Users must be authenticated to link an OAuth provider to an existing account.
            val existing = userRepository.findByEmail(email.lowercase().trim())
            if (existing != null) {
                throw WebApplicationException(
                    Response.status(409)
                        .entity(mapOf(
                            "error" to "conflict",
                            "message" to "An account with this email already exists. Log in with your password and link $provider from account settings.",
                            "status" to 409,
                        ))
                        .build()
                )
            }

            user = UserEntity().apply {
                id = generateId()
                this.email = email.lowercase().trim()
                this.name = name
                this.oauthProvider = provider
                this.oauthId = oauthId
                this.avatarUrl = avatarUrl
                // Use the verification status reported by the OAuth provider.
                // Google always verifies; GitHub requires an explicit check via /user/emails.
                this.emailVerified = emailVerified
                this.createdAt = Instant.now()
                this.updatedAt = Instant.now()
            }
            userRepository.persist(user)
            log.infof("Created OAuth user id=%s provider=%s", user.id, provider)

            if (appId != null) {
                val app = appRepository.findById(appId)
                if (app != null && app.requiresExplicitAccess) {
                    grantAccessInternal(user.id, appId, "user")
                }
            }
        }

        checkAppAccess(user, appId)
        return user.toView()
    }

    // ── Me / delete ───────────────────────────────────────────────────────────

    fun getById(userId: String): UserView =
        (userRepository.findById(userId) ?: throw NotFoundException("User not found")).toView()

    @Transactional
    fun deleteAccount(userId: String) {
        val user = userRepository.findById(userId) ?: throw NotFoundException("User not found")
        log.infof("AUDIT account_deleted userId=%s email=%s", user.id, user.email)
        revokeAllRefreshTokens(userId)
        userRepository.delete(user)
    }

    // ── App access management (called from AppResource) ───────────────────────

    @Transactional
    fun grantAccess(userId: String, appId: String, role: String = "user") {
        userRepository.findById(userId) ?: throw NotFoundException("User not found")
        appRepository.findById(appId) ?: throw NotFoundException("App not found")
        if (!accessRepository.hasAccess(userId, appId)) {
            grantAccessInternal(userId, appId, role)
        }
    }

    @Transactional
    fun revokeAccess(userId: String, appId: String) {
        if (!accessRepository.deleteAccess(userId, appId)) {
            throw NotFoundException("Access record not found")
        }
    }

    fun getRole(userId: String, appId: String): String? =
        accessRepository.findRole(userId, appId)

    fun listAccessByApp(appId: String): List<UserAppAccessEntity> =
        accessRepository.findByApp(appId)

    // ── Auth tokens (password reset / magic link / email verification) ─────────

    @Transactional
    fun createAuthToken(userId: String, type: String, expiresInHours: Long): String {
        val rawToken = generateToken()
        // Store only the HMAC of the token — a DB dump does not expose active secrets
        val entity = AuthTokenEntity().apply {
            id = generateId()
            this.userId = userId
            this.token = Hmac.sha256(rawToken, tokenPepper)
            this.type = type
            this.expiresAt = Instant.now().plus(expiresInHours, ChronoUnit.HOURS)
            this.used = false
            this.createdAt = Instant.now()
        }
        authTokenRepository.persist(entity)
        return rawToken
    }

    @Transactional
    fun consumeAuthToken(rawToken: String, expectedType: String): String {
        // Atomic UPDATE-before-SELECT eliminates the TOCTOU race where two concurrent
        // requests could both read used=false and both succeed.
        val entity = authTokenRepository.claimToken(Hmac.sha256(rawToken, tokenPepper), expectedType)
            ?: throw BadRequestException("Invalid or expired token")
        return entity.userId
    }

    // ── Refresh tokens ─────────────────────────────────────────────────────────

    /** Issue a new refresh token. Returns the raw (unhashed) token. */
    @Transactional
    fun issueRefreshToken(userId: String, appId: String?): String {
        val rawToken = generateToken()
        refreshTokenRepository.persist(RefreshTokenEntity().apply {
            id = generateId()
            this.userId = userId
            this.token = Hmac.sha256(rawToken, tokenPepper)
            this.appId = appId
            this.expiresAt = Instant.now().plusSeconds(refreshTokenExpirySeconds)
            this.revoked = false
            this.createdAt = Instant.now()
        })
        return rawToken
    }

    /**
     * Rotate a refresh token: atomically revokes the old one and issues a new one.
     * Returns (userId, appId, newRawRefreshToken) or throws if the token is invalid/expired/revoked.
     */
    @Transactional
    fun rotateRefreshToken(rawToken: String): Triple<String, String?, String> {
        val entity = refreshTokenRepository.claimToken(Hmac.sha256(rawToken, tokenPepper))
            ?: throw NotAuthorizedException("Invalid or expired refresh token", "Bearer")
        // Verify the user still exists
        userRepository.findById(entity.userId)
            ?: throw NotAuthorizedException("User no longer exists", "Bearer")
        val newRawToken = issueRefreshToken(entity.userId, entity.appId)
        return Triple(entity.userId, entity.appId, newRawToken)
    }

    /** Revoke all refresh tokens for a user (on account deletion). */
    @Transactional
    fun revokeAllRefreshTokens(userId: String) {
        refreshTokenRepository.revokeAllForUser(userId)
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    /** Validate that the app ID refers to a registered app. Returns null if appId is null. */
    fun validateAppId(appId: String?): String? {
        if (appId == null) return null
        appRepository.findById(appId)
            ?: throw BadRequestException("Unknown app: $appId")
        return appId
    }

    private fun checkAppAccess(user: UserEntity, appId: String?) {
        if (appId == null) return
        val app = appRepository.findById(appId)
            ?: throw BadRequestException("Unknown app: $appId")
        if (app.requiresExplicitAccess && !accessRepository.hasAccess(user.id, appId)) {
            throw ForbiddenException("You do not have access to this application")
        }
    }

    private fun grantAccessInternal(userId: String, appId: String, role: String) {
        val access = UserAppAccessEntity().apply {
            id = UserAppAccessId().apply {
                this.userId = userId
                this.appId = appId
            }
            this.role = role
            this.grantedAt = Instant.now()
        }
        accessRepository.persist(access)
    }

    private fun generateId(): String {
        val chars = "abcdefghijklmnopqrstuvwxyz0123456789"
        return "c" + (1..24).map { chars[secureRandom.nextInt(chars.length)] }.joinToString("")
    }

    private fun generateToken(): String {
        val bytes = ByteArray(32)
        secureRandom.nextBytes(bytes)
        return bytes.joinToString("") { "%02x".format(it) }
    }

    private fun UserEntity.toView() = UserView(
        id = id,
        email = email,
        name = name,
        emailVerified = emailVerified,
        avatarUrl = avatarUrl,
    )
}
