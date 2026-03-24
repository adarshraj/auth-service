package com.authservice.service

import com.authservice.config.OAuthConfig
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import jakarta.ws.rs.BadRequestException
import org.eclipse.microprofile.config.inject.ConfigProperty
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.charset.StandardCharsets

/**
 * Google and GitHub OAuth flows.
 * Ported directly from finance-tracker's oauth.ts — same endpoints, same flow.
 */
@ApplicationScoped
class OAuthService @Inject constructor(
    private val oauthConfig: OAuthConfig,
    @ConfigProperty(name = "auth.base-url", defaultValue = "http://localhost:8703") private val baseUrl: String,
) {
    private val http = HttpClient.newHttpClient()
    private val mapper = ObjectMapper()

    data class OAuthUser(
        val id: String,
        val email: String,
        val name: String,
        val avatarUrl: String?,
    )

    // ── Google ────────────────────────────────────────────────────────────────

    fun googleAuthUrl(state: String): String {
        val cfg = oauthConfig.google()
        if (cfg.clientId().isBlank()) throw BadRequestException("Google OAuth is not configured")
        val params = mapOf(
            "client_id" to cfg.clientId(),
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
            "client_id" to cfg.clientId(),
            "client_secret" to cfg.clientSecret(),
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
        )
    }

    // ── GitHub ────────────────────────────────────────────────────────────────

    fun githubAuthUrl(state: String): String {
        val cfg = oauthConfig.github()
        if (cfg.clientId().isBlank()) throw BadRequestException("GitHub OAuth is not configured")
        val params = mapOf(
            "client_id" to cfg.clientId(),
            "redirect_uri" to "$baseUrl/auth/oauth/callback?provider=github",
            "scope" to "user:email",
            "state" to state,
        ).toQueryString()
        return "https://github.com/login/oauth/authorize?$params"
    }

    fun exchangeGithubCode(code: String): OAuthUser {
        val cfg = oauthConfig.github()
        val tokenBody = mapper.writeValueAsString(mapOf(
            "client_id" to cfg.clientId(),
            "client_secret" to cfg.clientSecret(),
            "code" to code,
        ))

        val tokenRes = postJson("https://github.com/login/oauth/access_token", tokenBody,
            acceptJson = true)
        val accessToken = tokenRes["access_token"]?.asText()
            ?: throw BadRequestException("GitHub token exchange failed")

        val userRes = getGithub("https://api.github.com/user", accessToken)
        val email = userRes["email"]?.asText()?.takeIf { it.isNotBlank() }
            ?: fetchGithubPrimaryEmail(accessToken)

        return OAuthUser(
            id = userRes["id"]?.asText() ?: throw BadRequestException("Missing GitHub user id"),
            email = email,
            name = userRes["name"]?.asText() ?: userRes["login"]?.asText() ?: email.substringBefore('@'),
            avatarUrl = userRes["avatar_url"]?.asText(),
        )
    }

    private fun fetchGithubPrimaryEmail(accessToken: String): String {
        val emails = getGithub("https://api.github.com/user/emails", accessToken)
        if (emails.isArray) {
            val primary = emails.find { it["primary"]?.asBoolean() == true }
                ?: emails.firstOrNull()
            return primary?.get("email")?.asText() ?: throw BadRequestException("Email not available from GitHub")
        }
        throw BadRequestException("Email not available from GitHub")
    }

    // ── HTTP helpers ──────────────────────────────────────────────────────────

    private fun post(url: String, body: String, contentType: String): JsonNode {
        val req = HttpRequest.newBuilder(URI.create(url))
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .header("Content-Type", contentType)
            .header("Accept", "application/json")
            .build()
        val res = http.send(req, HttpResponse.BodyHandlers.ofString())
        if (res.statusCode() >= 400) throw BadRequestException("OAuth request failed: ${res.body()}")
        return mapper.readTree(res.body())
    }

    private fun postJson(url: String, body: String, acceptJson: Boolean): JsonNode =
        post(url, body, "application/json")

    private fun get(url: String, bearerToken: String): JsonNode {
        val req = HttpRequest.newBuilder(URI.create(url))
            .GET()
            .header("Authorization", "Bearer $bearerToken")
            .build()
        val res = http.send(req, HttpResponse.BodyHandlers.ofString())
        if (res.statusCode() >= 400) throw BadRequestException("OAuth userinfo failed: ${res.body()}")
        return mapper.readTree(res.body())
    }

    private fun getGithub(url: String, bearerToken: String): JsonNode {
        val req = HttpRequest.newBuilder(URI.create(url))
            .GET()
            .header("Authorization", "Bearer $bearerToken")
            .header("Accept", "application/vnd.github.v3+json")
            .build()
        val res = http.send(req, HttpResponse.BodyHandlers.ofString())
        if (res.statusCode() >= 400) throw BadRequestException("GitHub API failed: ${res.body()}")
        return mapper.readTree(res.body())
    }

    private fun Map<String, String>.toQueryString() =
        entries.joinToString("&") { (k, v) ->
            "${URLEncoder.encode(k, StandardCharsets.UTF_8)}=${URLEncoder.encode(v, StandardCharsets.UTF_8)}"
        }

    private fun Map<String, String>.toFormEncoded() = toQueryString()
}
