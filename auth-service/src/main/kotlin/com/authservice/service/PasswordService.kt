package com.authservice.service

import at.favre.lib.crypto.bcrypt.BCrypt
import jakarta.enterprise.context.ApplicationScoped

/**
 * bcrypt hash/verify — compatible with finance-tracker's bcrypt hashes (cost factor 10).
 * Existing hashes from finance-tracker can be imported directly; no re-hashing needed.
 */
@ApplicationScoped
class PasswordService {

    private val hasher = BCrypt.withDefaults()
    private val verifier = BCrypt.verifyer()

    fun hash(password: String): String =
        hasher.hashToString(10, password.toCharArray())

    fun verify(password: String, hash: String): Boolean =
        verifier.verify(password.toCharArray(), hash).verified
}
