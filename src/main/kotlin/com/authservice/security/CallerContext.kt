package com.authservice.security

/** Resolved JWT claims — set by JwtFilter on protected endpoints. */
data class CallerContext(
    val userId: String,
    val email: String,
    val appId: String?,
)
