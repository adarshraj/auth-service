package com.authservice.service

import com.authservice.domain.AppRepository
import com.authservice.domain.AuthTokenEntity
import com.authservice.domain.AuthTokenRepository
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
    private val passwordService: PasswordService,
    @ConfigProperty(name = "auth.token-pepper") private val tokenPepper: String,
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
        val normalizedEmail = email.lowercase().trim()
        if (userRepository.findByEmail(normalizedEmail) != null) {
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
        val user = userRepository.findByEmail(email.lowercase().trim())
            ?: throw NotAuthorizedException("Invalid email or password", "Bearer")

        if (user.passwordHash == null) {
            // Generic message — do not reveal that this email is registered via OAuth only (account enumeration)
            throw NotAuthorizedException("Invalid email or password", "Bearer")
        }

        if (!passwordService.verify(password, user.passwordHash!!)) {
            throw NotAuthorizedException("Invalid email or password", "Bearer")
        }

        checkAppAccess(user, appId)
        log.infof("Login user id=%s app=%s", user.id, appId ?: "none")
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
                this.emailVerified = true
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
        userRepository.delete(user)
        log.infof("Deleted account id=%s", userId)
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
        val entity = authTokenRepository.findByToken(Hmac.sha256(rawToken, tokenPepper))
            ?: throw BadRequestException("Invalid token")
        if (entity.used) throw BadRequestException("Token already used")
        if (entity.type != expectedType) throw BadRequestException("Invalid token type")
        if (entity.expiresAt.isBefore(Instant.now())) throw BadRequestException("Token expired")
        entity.used = true
        return entity.userId
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    private fun checkAppAccess(user: UserEntity, appId: String?) {
        if (appId == null) return
        val app = appRepository.findById(appId) ?: return
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
