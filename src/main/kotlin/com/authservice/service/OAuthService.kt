package com.authservice.service

import com.authservice.config.OAuthConfig
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import jakarta.ws.rs.BadRequestException
import org.eclipse.microprofile.config.inject.ConfigProperty
import org.jboss.logging.Logger
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.charset.StandardCharsets
import java.time.Duration

/**
 * Google and GitHub OAuth flows.
 * Ported directly from finance-tracker's oauth.ts — same endpoints, same flow.
 */
@ApplicationScoped
class OAuthService @Inject constructor(
    private val oauthConfig: OAuthConfig,
    @ConfigProperty(name = "auth.base-url", defaultValue = "http://localhost:8703") baseUrl: String,
) {
    // Normalize once — trailing slash on AUTH_BASE_URL must not produce double slashes in callback URLs
    private val baseUrl = baseUrl.trimEnd('/')
    companion object {
        private val log: Logger = Logger.getLogger(OAuthService::class.java)
        private val CONNECT_TIMEOUT = Duration.ofSeconds(10)
        private val REQUEST_TIMEOUT = Duration.ofSeconds(15)
    }

    private val http = HttpClient.newBuilder()
        .connectTimeout(CONNECT_TIMEOUT)
        .build()
    private val mapper = ObjectMapper()

    data class OAuthUser(
        val id: String,
        val email: String,
        val name: String,
        val avatarUrl: String?,
        /** Whether the OAuth provider has verified ownership of this email address. */
        val emailVerified: Boolean,
    )

    // ── Google ────────────────────────────────────────────────────────────────

    fun googleAuthUrl(state: String): String {
        val cfg = oauthConfig.google()
        val clientId = cfg.clientId().orElse("").takeIf { it.isNotBlank() }
            ?: throw BadRequestException("Google OAuth is not configured")
        val params = mapOf(
            "client_id" to clientId,
            "redirect_uri" to "$baseUrl/auth/oauth/callback?provider=google",
            "response_type" to "code",
            "scope" to "openid email profile",
            "state" to state,
            "access_type" to "offline",
            "prompt" to "consent",
        ).toQueryString()
        return "https://accounts.google.com/o/oauth2/v2/auth?$params"
    }

    fun exchangeGoogleCode(code: String): OAuthUser {
        val cfg = oauthConfig.google()
        val tokenBody = mapOf(
            "code" to code,
            "client_id" to cfg.clientId().orElse(""),
            "client_secret" to cfg.clientSecret().orElse(""),
            "redirect_uri" to "$baseUrl/auth/oauth/callback?provider=google",
            "grant_type" to "authorization_code",
        ).toFormEncoded()

        val tokenRes = post("https://oauth2.googleapis.com/token", tokenBody, "application/x-www-form-urlencoded")
        val accessToken = tokenRes["access_token"]?.asText() ?: throw BadRequestException("Google token exchange failed")

        val userRes = get("https://www.googleapis.com/oauth2/v2/userinfo", accessToken)
        return OAuthUser(
            id = userRes["id"]?.asText() ?: throw BadRequestException("Missing Google user id"),
            email = userRes["email"]?.asText() ?: throw BadRequestException("Missing Google email"),
            name = userRes["name"]?.asText() ?: userRes["email"]!!.asText().substringBefore('@'),
            avatarUrl = userRes["picture"]?.asText(),
            // Google's userinfo endpoint returns verified_email; default true if field is absent
            // (all Google accounts require a verified email to exist)
            emailVerified = userRes["verified_email"]?.asBoolean() ?: true,
        )
    }

    // ── GitHub ────────────────────────────────────────────────────────────────

    fun githubAuthUrl(state: String): String {
        val cfg = oauthConfig.github()
        val clientId = cfg.clientId().orElse("").takeIf { it.isNotBlank() }
            ?: throw BadRequestException("GitHub OAuth is not configured")
        val params = mapOf(
            "client_id" to clientId,
            "redirect_uri" to "$baseUrl/auth/oauth/callback?provider=github",
            "scope" to "user:email",
            "state" to state,
        ).toQueryString()
        return "https://github.com/login/oauth/authorize?$params"
    }

    fun exchangeGithubCode(code: String): OAuthUser {
        val cfg = oauthConfig.github()
        val tokenBody = mapper.writeValueAsString(mapOf(
            "client_id" to cfg.clientId().orElse(""),
            "client_secret" to cfg.clientSecret().orElse(""),
            "code" to code,
        ))

        val tokenRes = post("https://github.com/login/oauth/access_token", tokenBody, "application/json")
        val accessToken = tokenRes["access_token"]?.asText()
            ?: throw BadRequestException("GitHub token exchange failed")

        val userRes = getGithub("https://api.github.com/user", accessToken)
        // Always fetch from /user/emails to get the verified status — the /user endpoint
        // does not expose email verification state, and GitHub allows unverified email accounts.
        val emailResult = fetchGithubPrimaryEmail(accessToken)

        return OAuthUser(
            id = userRes["id"]?.asText() ?: throw BadRequestException("Missing GitHub user id"),
            email = emailResult.email,
            name = userRes["name"]?.asText() ?: userRes["login"]?.asText() ?: emailResult.email.substringBefore('@'),
            avatarUrl = userRes["avatar_url"]?.asText(),
            emailVerified = emailResult.verified,
        )
    }

    private data class GitHubEmailResult(val email: String, val verified: Boolean)

    private fun fetchGithubPrimaryEmail(accessToken: String): GitHubEmailResult {
        val emails = getGithub("https://api.github.com/user/emails", accessToken)
        if (emails.isArray) {
            val primary = emails.find { it["primary"]?.asBoolean() == true }
                ?: emails.firstOrNull()
            val email = primary?.get("email")?.asText() ?: throw BadRequestException("Email not available from GitHub")
            val verified = primary?.get("verified")?.asBoolean() ?: false
            return GitHubEmailResult(email, verified)
        }
        throw BadRequestException("Email not available from GitHub")
    }

    // ── HTTP helpers ──────────────────────────────────────────────────────────

    private fun post(url: String, body: String, contentType: String): JsonNode {
        val req = HttpRequest.newBuilder(URI.create(url))
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .header("Content-Type", contentType)
            .header("Accept", "application/json")
            .timeout(REQUEST_TIMEOUT)
            .build()
        val res = http.send(req, HttpResponse.BodyHandlers.ofString())
        if (res.statusCode() >= 400) {
            // Log detail server-side; never forward raw provider error to the client
            log.warnf("OAuth POST to %s failed with status %d: %s", url, res.statusCode(), res.body())
            throw BadRequestException("OAuth request failed")
        }
        return mapper.readTree(res.body())
    }

    private fun get(url: String, bearerToken: String): JsonNode {
        val req = HttpRequest.newBuilder(URI.create(url))
            .GET()
            .header("Authorization", "Bearer $bearerToken")
            .timeout(REQUEST_TIMEOUT)
            .build()
        val res = http.send(req, HttpResponse.BodyHandlers.ofString())
        if (res.statusCode() >= 400) {
            log.warnf("OAuth GET to %s failed with status %d: %s", url, res.statusCode(), res.body())
            throw BadRequestException("OAuth userinfo request failed")
        }
        return mapper.readTree(res.body())
    }

    private fun getGithub(url: String, bearerToken: String): JsonNode {
        val req = HttpRequest.newBuilder(URI.create(url))
            .GET()
            .header("Authorization", "Bearer $bearerToken")
            .header("Accept", "application/vnd.github.v3+json")
            .timeout(REQUEST_TIMEOUT)
            .build()
        val res = http.send(req, HttpResponse.BodyHandlers.ofString())
        if (res.statusCode() >= 400) {
            log.warnf("GitHub API GET to %s failed with status %d: %s", url, res.statusCode(), res.body())
            throw BadRequestException("GitHub API request failed")
        }
        return mapper.readTree(res.body())
    }

    private fun Map<String, String>.toQueryString() =
        entries.joinToString("&") { (k, v) ->
            "${URLEncoder.encode(k, StandardCharsets.UTF_8)}=${URLEncoder.encode(v, StandardCharsets.UTF_8)}"
        }

    private fun Map<String, String>.toFormEncoded() = toQueryString()
}
