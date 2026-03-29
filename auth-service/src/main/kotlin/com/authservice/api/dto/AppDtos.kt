package com.authservice.api.dto

import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Pattern

// ── Requests ──────────────────────────────────────────────────────────────────

data class CreateAppRequest(
    @field:NotBlank
    @field:Pattern(regexp = "[a-z0-9_-]+", message = "App id must be lowercase alphanumeric with hyphens/underscores")
    val id: String = "",
    @field:NotBlank val name: String = "",
    val requiresExplicitAccess: Boolean = false,
    val redirectUris: List<String> = emptyList(),
)

data class GrantAccessRequest(
    @field:jakarta.validation.constraints.Pattern(
        regexp = "[a-z][a-z0-9_-]{0,49}",
        message = "Role must start with a letter and contain only lowercase alphanumeric, hyphens, or underscores (max 50 chars)"
    )
    val role: String = "user",
)

// ── Responses ────────────────────────────────────────────────────────────────

data class AppResponse(
    val id: String,
    val name: String,
    val requiresExplicitAccess: Boolean,
    val redirectUris: List<String>,
    val createdAt: String,
)

data class AccessResponse(
    val userId: String,
    val appId: String,
    val role: String,
    val grantedAt: String,
)
