package com.authservice.security

import io.quarkus.runtime.StartupEvent
import jakarta.enterprise.context.ApplicationScoped
import jakarta.enterprise.event.Observes
import jakarta.inject.Inject
import org.eclipse.microprofile.config.inject.ConfigProperty
import org.jboss.logging.Logger
import java.util.Optional

@ApplicationScoped
class StartupGuard @Inject constructor(
    @ConfigProperty(name = "quarkus.profile", defaultValue = "dev") private val profile: String,
    @ConfigProperty(name = "auth.admin-key") private val adminKey: Optional<String>,
    @ConfigProperty(name = "auth.key-hmac-secret") private val hmacSecret: String,
    @ConfigProperty(name = "auth.state-hmac-secret") private val stateHmacSecret: String,
    @ConfigProperty(name = "auth.token-pepper") private val tokenPepper: String,
) {
    companion object {
        private val log: Logger = Logger.getLogger(StartupGuard::class.java)
        private val DEV_DEFAULTS = setOf(
            "dev-only-insecure-hmac-secret-change-in-prod",
            "dev-only-insecure-state-secret-change-in-prod",
            "dev-only-insecure-token-pepper-change-in-prod",
        )
    }

    fun onStart(@Observes ev: StartupEvent) {
        checkSecret("auth.key-hmac-secret / AUTH_KEY_HMAC_SECRET", hmacSecret)
        checkSecret("auth.state-hmac-secret / AUTH_STATE_HMAC_SECRET", stateHmacSecret)
        checkSecret("auth.token-pepper / AUTH_TOKEN_PEPPER", tokenPepper)
        checkAdminKey()
    }

    private fun checkSecret(name: String, value: String) {
        if (value in DEV_DEFAULTS) {
            val msg = "$name is using the default dev value. Set it to a unique secret in production."
            if (isProd()) throw IllegalStateException(msg) else log.warn(msg)
        } else if (isProd() && value.length < 32) {
            throw IllegalStateException("$name must be at least 32 characters in production (got ${value.length}).")
        }
    }

    private fun checkAdminKey() {
        if (adminKey.orElse(null)?.isBlank() != false) {
            log.warn("AUTH_ADMIN_KEY is not set — app management endpoints (/auth/apps) are disabled.")
        }
    }

    private fun isProd() = profile == "prod"
}
