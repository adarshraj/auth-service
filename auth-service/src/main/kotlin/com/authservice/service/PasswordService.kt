package com.authservice.service

import at.favre.lib.crypto.bcrypt.BCrypt
import jakarta.enterprise.context.ApplicationScoped

/**
 * bcrypt hash/verify.
 *
 * Cost factor 12 per OWASP recommendation. Existing cost-10 hashes from finance-tracker
 * remain verifiable (bcrypt encodes the cost in the hash); new hashes use cost 12.
 */
@ApplicationScoped
class PasswordService {

    private val hasher = BCrypt.withDefaults()
    private val verifier = BCrypt.verifyer()

    /** Common passwords that are rejected regardless of length. Loaded once at startup. */
    private val commonPasswords: Set<String> = javaClass.getResourceAsStream("/common-passwords.txt")
        ?.bufferedReader()?.readLines()
        ?.map { it.trim().lowercase() }
        ?.filter { it.isNotBlank() }
        ?.toSet()
        ?: emptySet()

    fun hash(password: String): String =
        hasher.hashToString(12, password.toCharArray())

    fun verify(password: String, hash: String): Boolean =
        verifier.verify(password.toCharArray(), hash).verified

    /** Returns true if the password is in the common/breached passwords list. */
    fun isCommon(password: String): Boolean =
        password.lowercase() in commonPasswords

    /**
     * Pre-computed cost-12 bcrypt hash used for timing equalization.
     * Verifying against this takes the same time as verifying against a real hash,
     * preventing timing side-channels that reveal whether an email is registered.
     */
    private val dummyHash: String = hasher.hashToString(12, "dummy-timing-equalization".toCharArray())

    /**
     * Perform a dummy hash to equalize timing on registration failure paths.
     * Prevents timing side-channels that reveal whether an email is registered.
     */
    fun dummyHash() {
        hasher.hashToString(12, "dummy-timing-equalization".toCharArray())
    }

    /**
     * Perform a dummy verify to equalize timing on login failure paths.
     * Uses a pre-computed hash so the cost matches a real bcrypt verify.
     */
    fun dummyVerify(password: String) {
        verifier.verify(password.toCharArray(), dummyHash)
    }
}
