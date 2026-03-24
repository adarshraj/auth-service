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
)

data class GrantAccessRequest(
    val role: String = "user",
)

// ── Responses ────────────────────────────────────────────────────────────────

data class AppResponse(
    val id: String,
    val name: String,
    val requiresExplicitAccess: Boolean,
    val createdAt: String,
)

data class AccessResponse(
    val userId: String,
    val appId: String,
    val role: String,
    val grantedAt: String,
)
