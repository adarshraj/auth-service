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
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.time.Instant
import java.time.temporal.ChronoUnit
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

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
        val normalizedEmail = email.lowercase().trim()
        val user = userRepository.findByEmail(normalizedEmail)
            ?: run {
                log.infof("AUDIT login_failed reason=unknown_email email=%s app=%s", normalizedEmail, appId ?: "none")
                throw NotAuthorizedException("Invalid email or password", "Bearer")
            }

        if (user.passwordHash == null) {
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
    fun createAuthToken(userId: String, type: String, expiresInHours: Long = 0, expiresInSeconds: Long = 0, appId: String? = null): String {
        val rawToken = generateToken()
        val expiry = if (expiresInSeconds > 0) {
            Instant.now().plus(expiresInSeconds, ChronoUnit.SECONDS)
        } else {
            Instant.now().plus(expiresInHours, ChronoUnit.HOURS)
        }
        // Store only the HMAC of the token — a DB dump does not expose active secrets
        val entity = AuthTokenEntity().apply {
            id = generateId()
            this.userId = userId
            this.token = Hmac.sha256(rawToken, tokenPepper)
            this.type = type
            this.appId = appId
            this.expiresAt = expiry
            this.used = false
            this.createdAt = Instant.now()
        }
        authTokenRepository.persist(entity)
        return rawToken
    }

    /**
     * Atomically consume a single-use auth token.
     * Uses UPDATE-before-SELECT to eliminate TOCTOU races (same pattern as OAuthCodeRepository.claimCode).
     * Returns (userId, appId).
     */
    @Transactional
    fun consumeAuthToken(rawToken: String, expectedType: String): Pair<String, String?> {
        val entity = authTokenRepository.claimToken(Hmac.sha256(rawToken, tokenPepper), expectedType)
            ?: throw BadRequestException("Invalid or expired token")
        return Pair(entity.userId, entity.appId)
    }

    // ── MFA ──────────────────────────────────────────────────────────────────

    fun isMfaEnabled(userId: String): Boolean =
        (userRepository.findById(userId) ?: throw NotFoundException("User not found")).mfaEnabled

    @Transactional
    fun setupMfa(userId: String, secret: String, backupCodes: List<String>) {
        val user = userRepository.findById(userId) ?: throw NotFoundException("User not found")
        if (user.mfaEnabled) throw BadRequestException("MFA is already enabled")
        // Encrypt the TOTP secret so a DB dump does not expose second-factor material.
        // Backup codes are stored as HMAC hashes — same pattern as auth tokens.
        user.mfaSecret = encryptMfaSecret(secret)
        user.mfaBackupCodes = backupCodes.joinToString(",") { Hmac.sha256(it, tokenPepper) }
        user.updatedAt = Instant.now()
    }

    @Transactional
    fun confirmMfa(userId: String) {
        val user = userRepository.findById(userId) ?: throw NotFoundException("User not found")
        if (user.mfaSecret == null) throw BadRequestException("MFA setup not started")
        if (user.mfaEnabled) throw BadRequestException("MFA is already enabled")
        user.mfaEnabled = true
        user.updatedAt = Instant.now()
        log.infof("AUDIT mfa_enabled userId=%s", userId)
    }

    @Transactional
    fun disableMfa(userId: String) {
        val user = userRepository.findById(userId) ?: throw NotFoundException("User not found")
        if (!user.mfaEnabled) throw BadRequestException("MFA is not enabled")
        user.mfaEnabled = false
        user.mfaSecret = null
        user.mfaBackupCodes = null
        user.updatedAt = Instant.now()
        log.infof("AUDIT mfa_disabled userId=%s", userId)
    }

    fun getMfaSecret(userId: String): String? {
        val encrypted = (userRepository.findById(userId) ?: throw NotFoundException("User not found")).mfaSecret
            ?: return null
        return decryptMfaSecret(encrypted)
    }

    @Transactional
    fun consumeBackupCode(userId: String, code: String): Boolean {
        val user = userRepository.findById(userId) ?: throw NotFoundException("User not found")
        val hashes = user.mfaBackupCodes?.split(",")?.toMutableList() ?: return false
        val codeHash = Hmac.sha256(code.lowercase().trim(), tokenPepper)
        if (!hashes.remove(codeHash)) return false
        user.mfaBackupCodes = hashes.joinToString(",")
        user.updatedAt = Instant.now()
        log.infof("AUDIT mfa_backup_code_used userId=%s", userId)
        return true
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

    /** AES-256-GCM encrypt using first 32 bytes of SHA-256(tokenPepper) as key. */
    private fun encryptMfaSecret(plaintext: String): String {
        val keyBytes = java.security.MessageDigest.getInstance("SHA-256")
            .digest(tokenPepper.toByteArray(StandardCharsets.UTF_8))
        val iv = ByteArray(12).also { secureRandom.nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(keyBytes, "AES"), GCMParameterSpec(128, iv))
        val ciphertext = cipher.doFinal(plaintext.toByteArray(StandardCharsets.UTF_8))
        // Store as iv:ciphertext in base64
        val ivB64 = java.util.Base64.getEncoder().encodeToString(iv)
        val ctB64 = java.util.Base64.getEncoder().encodeToString(ciphertext)
        return "$ivB64:$ctB64"
    }

    private fun decryptMfaSecret(encrypted: String): String {
        val keyBytes = java.security.MessageDigest.getInstance("SHA-256")
            .digest(tokenPepper.toByteArray(StandardCharsets.UTF_8))
        val parts = encrypted.split(":")
        if (parts.size != 2) throw BadRequestException("Corrupted MFA secret")
        val iv = java.util.Base64.getDecoder().decode(parts[0])
        val ciphertext = java.util.Base64.getDecoder().decode(parts[1])
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(keyBytes, "AES"), GCMParameterSpec(128, iv))
        return String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8)
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
