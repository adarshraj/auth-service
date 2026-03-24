package com.authservice

import com.authservice.domain.AppEntity
import com.authservice.domain.AppRepository
import com.authservice.domain.AuthTokenRepository
import com.authservice.domain.UserAppAccessRepository
import com.authservice.domain.UserRepository
import io.quarkus.test.junit.QuarkusTest
import io.restassured.RestAssured.given
import io.restassured.http.ContentType
import jakarta.inject.Inject
import jakarta.transaction.Transactional
import org.hamcrest.CoreMatchers.equalTo
import org.hamcrest.CoreMatchers.notNullValue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Instant

@QuarkusTest
class AuthResourceTest {

    @Inject lateinit var userRepository: UserRepository
    @Inject lateinit var appRepository: AppRepository
    @Inject lateinit var accessRepository: UserAppAccessRepository
    @Inject lateinit var authTokenRepository: AuthTokenRepository

    @BeforeEach
    @Transactional
    fun cleanup() {
        authTokenRepository.deleteAll()
        accessRepository.deleteAll()
        userRepository.deleteAll()
        appRepository.deleteAll()
    }

    // ── Register ──────────────────────────────────────────────────────────────

    @Test
    fun `register returns 201 with token and user`() {
        given()
            .contentType(ContentType.JSON)
            .body("""{"email":"alice@example.com","password":"password123","name":"Alice"}""")
        .`when`().post("/auth/register")
        .then()
            .statusCode(201)
            .body("token", notNullValue())
            .body("user.email", equalTo("alice@example.com"))
            .body("user.name", equalTo("Alice"))
            .body("user.id", notNullValue())
            .body("user.emailVerified", equalTo(false))
    }

    @Test
    fun `register normalises email to lowercase`() {
        given()
            .contentType(ContentType.JSON)
            .body("""{"email":"BOB@EXAMPLE.COM","password":"password123"}""")
        .`when`().post("/auth/register")
        .then()
            .statusCode(201)
            .body("user.email", equalTo("bob@example.com"))
    }

    @Test
    fun `register without name defaults to email prefix`() {
        given()
            .contentType(ContentType.JSON)
            .body("""{"email":"carol@example.com","password":"password123"}""")
        .`when`().post("/auth/register")
        .then()
            .statusCode(201)
            .body("user.name", equalTo("carol"))
    }

    @Test
    fun `register duplicate email returns 400`() {
        val body = """{"email":"dup@example.com","password":"password123"}"""
        given().contentType(ContentType.JSON).body(body).`when`().post("/auth/register").then().statusCode(201)

        given()
            .contentType(ContentType.JSON)
            .body(body)
        .`when`().post("/auth/register")
        .then()
            .statusCode(400)
            .body("error", equalTo("bad_request"))
    }

    @Test
    fun `register with short password returns 400`() {
        given()
            .contentType(ContentType.JSON)
            .body("""{"email":"short@example.com","password":"short"}""")
        .`when`().post("/auth/register")
        .then()
            .statusCode(400)
    }

    @Test
    fun `register with invalid email returns 400`() {
        given()
            .contentType(ContentType.JSON)
            .body("""{"email":"not-an-email","password":"password123"}""")
        .`when`().post("/auth/register")
        .then()
            .statusCode(400)
    }

    // ── Login ─────────────────────────────────────────────────────────────────

    @Test
    fun `login returns token`() {
        register("dave@example.com", "password123")

        given()
            .contentType(ContentType.JSON)
            .body("""{"email":"dave@example.com","password":"password123"}""")
        .`when`().post("/auth/login")
        .then()
            .statusCode(200)
            .body("token", notNullValue())
            .body("user.email", equalTo("dave@example.com"))
    }

    @Test
    fun `login is case-insensitive for email`() {
        register("EVE@EXAMPLE.COM", "password123")

        given()
            .contentType(ContentType.JSON)
            .body("""{"email":"eve@example.com","password":"password123"}""")
        .`when`().post("/auth/login")
        .then()
            .statusCode(200)
    }

    @Test
    fun `login wrong password returns 401`() {
        register("frank@example.com", "correct-password")

        given()
            .contentType(ContentType.JSON)
            .body("""{"email":"frank@example.com","password":"wrong-password"}""")
        .`when`().post("/auth/login")
        .then()
            .statusCode(401)
            .body("error", equalTo("unauthorized"))
    }

    @Test
    fun `login unknown email returns 401`() {
        given()
            .contentType(ContentType.JSON)
            .body("""{"email":"ghost@example.com","password":"password123"}""")
        .`when`().post("/auth/login")
        .then()
            .statusCode(401)
            .body("error", equalTo("unauthorized"))
    }

    @Test
    fun `login with blank password returns 400`() {
        given()
            .contentType(ContentType.JSON)
            .body("""{"email":"grace@example.com","password":""}""")
        .`when`().post("/auth/login")
        .then()
            .statusCode(400)
    }

    // ── Logout ────────────────────────────────────────────────────────────────

    @Test
    fun `logout returns 200`() {
        given()
        .`when`().post("/auth/logout")
        .then()
            .statusCode(200)
            .body("message", equalTo("Logged out"))
    }

    // ── Me ────────────────────────────────────────────────────────────────────

    @Test
    fun `me returns current user for valid token`() {
        val token = registerAndGetToken("henry@example.com", "password123")

        given()
            .header("Authorization", "Bearer $token")
        .`when`().get("/auth/me")
        .then()
            .statusCode(200)
            .body("email", equalTo("henry@example.com"))
            .body("id", notNullValue())
    }

    @Test
    fun `me returns 401 with no token`() {
        given()
        .`when`().get("/auth/me")
        .then()
            .statusCode(401)
            .body("error", equalTo("unauthorized"))
    }

    @Test
    fun `me returns 401 with garbage token`() {
        given()
            .header("Authorization", "Bearer not.a.jwt")
        .`when`().get("/auth/me")
        .then()
            .statusCode(401)
            .body("error", equalTo("unauthorized"))
    }

    @Test
    fun `me returns 401 with malformed Authorization header`() {
        given()
            .header("Authorization", "Basic dXNlcjpwYXNz")
        .`when`().get("/auth/me")
        .then()
            .statusCode(401)
    }

    // ── Delete account ────────────────────────────────────────────────────────

    @Test
    fun `deleteAccount removes user and returns 204`() {
        val token = registerAndGetToken("ivan@example.com", "password123")

        given()
            .header("Authorization", "Bearer $token")
        .`when`().delete("/auth/account")
        .then()
            .statusCode(204)

        // Subsequent me call returns 404 (user gone, but token is still valid signature-wise)
        given()
            .header("Authorization", "Bearer $token")
        .`when`().get("/auth/me")
        .then()
            .statusCode(404)
    }

    @Test
    fun `deleteAccount without token returns 401`() {
        given()
        .`when`().delete("/auth/account")
        .then()
            .statusCode(401)
    }

    // ── OAuth error paths ─────────────────────────────────────────────────────

    @Test
    fun `oauth callback with error param returns 400`() {
        given()
            .queryParam("error", "access_denied")
        .`when`().get("/auth/oauth/callback")
        .then()
            .statusCode(400)
            .body("error", equalTo("bad_request"))
    }

    @Test
    fun `oauth callback without code returns 400`() {
        given()
            .queryParam("state", "google::abc123")
        .`when`().get("/auth/oauth/callback")
        .then()
            .statusCode(400)
            .body("error", equalTo("bad_request"))
    }

    @Test
    fun `oauth redirect for unknown provider returns 400`() {
        given()
        .`when`().get("/auth/oauth/nosuchprovider")
        .then()
            .statusCode(400)
            .body("error", equalTo("bad_request"))
    }

    @Test
    fun `oauth redirect for google without client-id configured returns 400`() {
        // Test profile has no GOOGLE_CLIENT_ID set
        given()
        .`when`().get("/auth/oauth/google")
        .then()
            .statusCode(400)
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private fun register(email: String, password: String) {
        given()
            .contentType(ContentType.JSON)
            .body("""{"email":"$email","password":"$password"}""")
        .`when`().post("/auth/register")
        .then()
            .statusCode(201)
    }

    private fun registerAndGetToken(email: String, password: String): String {
        return given()
            .contentType(ContentType.JSON)
            .body("""{"email":"$email","password":"$password"}""")
        .`when`().post("/auth/register")
        .then()
            .statusCode(201)
            .extract().path("token")
    }
}
