package com.authservice.service

import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import org.eclipse.microprofile.config.inject.ConfigProperty
import org.jboss.logging.Logger

/**
 * Orchestrates email verification for a newly-registered user:
 *
 *   1. Ask [UserService] to mint a single-use `email_verification` auth token
 *   2. Render a minimal HTML + plain-text body with the verification link
 *   3. Post it to email-service via [MailClient]
 *
 * Exceptions are caught and logged — a transient email-service outage must NOT fail user
 * registration. The user can trigger a resend later via a separate endpoint (not implemented
 * here; that's a follow-up once the path is proven).
 */
@ApplicationScoped
class EmailVerificationService @Inject constructor(
    private val userService: UserService,
    private val mailClient: MailClient,
    @ConfigProperty(name = "auth.base-url", defaultValue = "http://localhost:8703")
    baseUrl: String,
    @ConfigProperty(name = "auth.email-verification.expiry-hours", defaultValue = "24")
    private val expiryHours: Long,
    @ConfigProperty(name = "auth.email-verification.from", defaultValue = "noreply@localhost")
    private val fromAddress: String,
) {
    private val baseUrl = baseUrl.trimEnd('/')

    companion object {
        private val log: Logger = Logger.getLogger(EmailVerificationService::class.java)
        private const val TOKEN_TYPE = "email_verification"
    }

    /** Best-effort send; swallows any exception and logs it. Returns true on success. */
    fun sendVerificationEmail(userId: String, toEmail: String, displayName: String?): Boolean {
        return try {
            val token = userService.createAuthToken(userId, TOKEN_TYPE, expiresInHours = expiryHours)
            val link = "$baseUrl/auth/email/verify?token=$token"
            val name = displayName?.takeIf { it.isNotBlank() } ?: "there"

            mailClient.send(
                MailClient.MailSendRequest(
                    from = fromAddress,
                    to = listOf(toEmail),
                    subject = "Verify your email",
                    html = renderHtml(name, link),
                    text = renderText(name, link),
                    tag = "verify-email",
                )
            )
            true
        } catch (e: Exception) {
            log.warnf("Failed to send verification email to %s: %s", toEmail, e.message)
            false
        }
    }

    private fun renderHtml(name: String, link: String): String = """
        <!doctype html>
        <html>
          <body style="font-family: -apple-system, Segoe UI, Roboto, sans-serif; max-width: 480px; margin: 0 auto; padding: 24px; color: #222;">
            <h2>Hi $name,</h2>
            <p>Thanks for signing up. Please confirm your email address by clicking the button below — the link expires in $expiryHours hours.</p>
            <p><a href="$link" style="display: inline-block; padding: 12px 24px; background: #3b82f6; color: #fff; text-decoration: none; border-radius: 6px;">Verify email</a></p>
            <p style="color: #666; font-size: 13px;">If the button doesn't work, paste this link into your browser:<br><code>$link</code></p>
            <hr style="border: none; border-top: 1px solid #eee; margin: 24px 0;">
            <p style="color: #999; font-size: 12px;">If you didn't create this account, you can safely ignore this email.</p>
          </body>
        </html>
    """.trimIndent()

    private fun renderText(name: String, link: String): String = """
        Hi $name,

        Thanks for signing up. Please confirm your email address by visiting:

        $link

        The link expires in $expiryHours hours.

        If you didn't create this account, you can safely ignore this email.
    """.trimIndent()
}
