package com.authservice

import com.authservice.domain.AppRepository
import com.authservice.domain.AuthTokenRepository
import com.authservice.domain.UserAppAccessRepository
import com.authservice.domain.UserRepository
import com.authservice.security.RateLimiter
import io.quarkus.test.junit.QuarkusTest
import io.quarkus.test.junit.QuarkusTestProfile
import io.quarkus.test.junit.TestProfile
import io.restassured.RestAssured.given
import io.restassured.http.ContentType
import jakarta.inject.Inject
import jakarta.transaction.Transactional
import org.hamcrest.CoreMatchers.equalTo
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * Enables rate limiting with RPM=2 for this test class only.
 * The test profile overrides the %test profile which disables rate limiting.
 */
class RateLimitTestProfile : QuarkusTestProfile {
    override fun getConfigOverrides(): Map<String, String> = mapOf(
        "auth.rate-limit.enabled" to "true",
        "auth.rate-limit.requests-per-minute" to "2",
    )
}

@QuarkusTest
@TestProfile(RateLimitTestProfile::class)
class RateLimitTest {

    @Inject lateinit var userRepository: UserRepository
    @Inject lateinit var appRepository: AppRepository
    @Inject lateinit var accessRepository: UserAppAccessRepository
    @Inject lateinit var authTokenRepository: AuthTokenRepository
    @Inject lateinit var rateLimiter: RateLimiter

    @BeforeEach
    @Transactional
    fun cleanup() {
        authTokenRepository.deleteAll()
        accessRepository.deleteAll()
        userRepository.deleteAll()
        appRepository.deleteAll()
        rateLimiter.resetAll()
    }

    @Test
    fun `rate limit returns 429 after burst on register endpoint`() {
        // First 2 requests (unique emails so they succeed with 201)
        repeat(2) { i ->
            given()
                .contentType(ContentType.JSON)
                .body("""{"email":"rl$i@example.com","password":"password123"}""")
            .`when`().post("/auth/register")
            .then()
                .statusCode(201)
        }

        // Third request from the same IP bucket hits the limit
        given()
            .contentType(ContentType.JSON)
            .body("""{"email":"rl3@example.com","password":"password123"}""")
        .`when`().post("/auth/register")
        .then()
            .statusCode(429)
            .body("error", equalTo("too_many_requests"))
            .body("status", equalTo(429))
            .header("Retry-After", equalTo("60"))
    }

    @Test
    fun `rate limit applies to login endpoint too`() {
        // Pre-register 3 users via direct injection to avoid consuming rate limit budget
        // (rate limiting is keyed by IP, and all requests from RestAssured share the same IP)
        // Instead, we exhaust the limit by registering, then verify login also gets blocked.

        given()
            .contentType(ContentType.JSON)
            .body("""{"email":"limited@example.com","password":"password123"}""")
        .`when`().post("/auth/register")
        .then()
            .statusCode(201)

        given()
            .contentType(ContentType.JSON)
            .body("""{"email":"limited2@example.com","password":"password123"}""")
        .`when`().post("/auth/register")
        .then()
            .statusCode(201)

        // Bucket is now at limit — login should be blocked
        given()
            .contentType(ContentType.JSON)
            .body("""{"email":"limited@example.com","password":"password123"}""")
        .`when`().post("/auth/login")
        .then()
            .statusCode(429)
            .body("error", equalTo("too_many_requests"))
    }
}
