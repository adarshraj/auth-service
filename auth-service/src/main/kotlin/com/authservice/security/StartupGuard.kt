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
) {
    companion object {
        private val log: Logger = Logger.getLogger(StartupGuard::class.java)
        private const val DEFAULT_HMAC = "dev-only-insecure-hmac-secret-change-in-prod"
    }

    fun onStart(@Observes ev: StartupEvent) {
        checkHmacSecret()
        checkAdminKey()
    }

    private fun checkHmacSecret() {
        if (hmacSecret == DEFAULT_HMAC) {
            val msg = "auth.key-hmac-secret is using the default dev value. Set AUTH_KEY_HMAC_SECRET in production."
            if (isProd()) throw IllegalStateException(msg) else log.warn(msg)
        }
    }

    private fun checkAdminKey() {
        if (adminKey.orElse(null)?.isBlank() != false) {
            log.warn("AUTH_ADMIN_KEY is not set — app management endpoints (/auth/apps) are disabled.")
        }
    }

    private fun isProd() = profile == "prod"
}
