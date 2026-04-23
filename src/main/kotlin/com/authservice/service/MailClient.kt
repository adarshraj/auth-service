package com.authservice.service

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import org.eclipse.microprofile.config.inject.ConfigProperty
import org.jboss.logging.Logger
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import java.time.Instant

/**
 * HTTP client for the platform email-service.
 *
 * Mints a short-lived service JWT via [JwtService] using a synthetic "email-sender" identity
 * keyed off the auth-service itself, and caches it until close to expiry. email-service verifies
 * the same JWT via the shared JWKS endpoint, so no extra credential plumbing is needed.
 *
 * Sync: one POST per call, no queue. Intentionally simple — if email-service is down, the caller
 * sees the failure and can decide whether to swallow it (e.g. verification email on signup) or
 * surface it (e.g. a manual "resend verification" button).
 */
@ApplicationScoped
class MailClient @Inject constructor(
    private val jwtService: JwtService,
    @ConfigProperty(name = "auth.email-service.base-url", defaultValue = "http://localhost:8706")
    baseUrl: String,
    @ConfigProperty(name = "auth.email-service.enabled", defaultValue = "false")
    private val enabled: Boolean,
    @ConfigProperty(name = "auth.email-service.service-user-id", defaultValue = "svc-auth-service")
    private val serviceUserId: String,
    @ConfigProperty(name = "auth.email-service.service-email", defaultValue = "svc-auth-service@internal")
    private val serviceEmail: String,
) {
    companion object {
        private val log: Logger = Logger.getLogger(MailClient::class.java)
        private val CONNECT_TIMEOUT = Duration.ofSeconds(5)
        private val REQUEST_TIMEOUT = Duration.ofSeconds(10)
        // Refresh the service token with a margin before it actually expires to avoid races.
        private val TOKEN_REFRESH_MARGIN = Duration.ofMinutes(5)
    }

    private val endpoint = baseUrl.trimEnd('/') + "/mail/send"
    private val http = HttpClient.newBuilder().connectTimeout(CONNECT_TIMEOUT).build()
    private val mapper = ObjectMapper()

    @Volatile private var cachedToken: String? = null
    @Volatile private var cachedTokenExpiry: Instant = Instant.EPOCH

    data class MailSendRequest(
        val to: List<String>,
        val subject: String,
        val html: String? = null,
        val text: String? = null,
        val from: String? = null,
        val replyTo: String? = null,
        val tag: String? = null,
    )

    /** Throws [RuntimeException] on any non-2xx response. Caller decides how to recover. */
    fun send(request: MailSendRequest): String? {
        if (!enabled) {
            log.debugf("MailClient disabled — skipping send tag=%s to=%s", request.tag, request.to)
            return null
        }
        val body = buildBody(request)
        val token = currentServiceToken()

        val httpRequest = HttpRequest.newBuilder()
            .uri(URI.create(endpoint))
            .timeout(REQUEST_TIMEOUT)
            .header("Authorization", "Bearer $token")
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build()

        val response = http.send(httpRequest, HttpResponse.BodyHandlers.ofString())
        if (response.statusCode() >= 400) {
            val snippet = response.body().take(500)
            throw RuntimeException("email-service returned ${response.statusCode()}: $snippet")
        }
        val node: JsonNode = mapper.readTree(response.body())
        val messageId = node.path("message_id").takeIf { !it.isMissingNode && !it.isNull }?.asText()
        log.infof("email sent tag=%s messageId=%s", request.tag, messageId)
        return messageId
    }

    private fun buildBody(r: MailSendRequest): String {
        val root = mapper.createObjectNode()
        r.from?.let { root.put("from", it) }
        val toArr = root.putArray("to")
        r.to.forEach { toArr.add(it) }
        r.replyTo?.let { root.put("reply_to", it) }
        root.put("subject", r.subject)
        r.html?.let { root.put("html", it) }
        r.text?.let { root.put("text", it) }
        r.tag?.let { root.put("tag", it) }
        return mapper.writeValueAsString(root)
    }

    /** Returns a valid service JWT, minting a new one if none is cached or the cached one is near expiry. */
    private fun currentServiceToken(): String {
        val now = Instant.now()
        val existing = cachedToken
        if (existing != null && cachedTokenExpiry.isAfter(now.plus(TOKEN_REFRESH_MARGIN))) {
            return existing
        }
        // JwtService hands out tokens with the configured expiry (default 7 days). That's more
        // than we need but there's no dedicated short-lived path today — the cache ensures we
        // mint infrequently regardless.
        val fresh = jwtService.sign(serviceUserId, serviceEmail, appId = null, role = "service")
        cachedToken = fresh
        cachedTokenExpiry = now.plus(Duration.ofHours(1))
        return fresh
    }
}
