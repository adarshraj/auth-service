package com.authservice.api.dto

import jakarta.validation.constraints.Email
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Size

// ── Requests ──────────────────────────────────────────────────────────────────

data class RegisterRequest(
    @field:NotBlank @field:Email val email: String = "",
    // password is intentionally optional — supports OAuth-only accounts created via the OAuth flow.
    // Callers registering a password account must supply a value; bcrypt validation is in PasswordService.
    @field:Size(min = 8, message = "Password must be at least 8 characters") val password: String? = null,
    val name: String? = null,
)

data class LoginRequest(
    @field:NotBlank @field:Email val email: String = "",
    @field:NotBlank val password: String = "",
)

// ── Responses ────────────────────────────────────────────────────────────────

data class UserResponse(
    val id: String,
    val email: String,
    val name: String?,
    val emailVerified: Boolean,
    val avatarUrl: String?,
)

data class AuthResponse(
    val token: String,
    val user: UserResponse,
)

/** Returned instead of AuthResponse when the user has MFA enabled. */
data class MfaChallengeResponse(
    val mfaRequired: Boolean = true,
    val mfaToken: String,
)

data class MfaVerifyRequest(
    @field:NotBlank val mfaToken: String = "",
    @field:NotBlank val code: String = "",
)

data class MfaSetupResponse(
    val secret: String,
    val otpauthUri: String,
    val recoveryCodes: List<String>,
)

data class MfaConfirmRequest(
    @field:NotBlank val code: String = "",
)

data class MfaDisableRequest(
    @field:NotBlank val code: String = "",
)
