package com.authservice

import com.authservice.domain.AppRepository
import com.authservice.domain.AuthTokenRepository
import com.authservice.domain.RefreshTokenRepository
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

@QuarkusTest
class AppResourceTest {

    @Inject lateinit var userRepository: UserRepository
    @Inject lateinit var appRepository: AppRepository
    @Inject lateinit var accessRepository: UserAppAccessRepository
    @Inject lateinit var authTokenRepository: AuthTokenRepository
    @Inject lateinit var refreshTokenRepository: RefreshTokenRepository

    private val adminKey = "test-admin-key"

    @BeforeEach
    @Transactional
    fun cleanup() {
        refreshTokenRepository.deleteAll()
        authTokenRepository.deleteAll()
        accessRepository.deleteAll()
        userRepository.deleteAll()
        appRepository.deleteAll()
    }

    // ── App CRUD ──────────────────────────────────────────────────────────────

    @Test
    fun `create app returns 201 with app details`() {
        given()
            .header("X-Admin-Key", adminKey)
            .contentType(ContentType.JSON)
            .body("""{"id":"my-app","name":"My App","requiresExplicitAccess":false}""")
        .`when`().post("/auth/apps")
        .then()
            .statusCode(201)
            .body("id", equalTo("my-app"))
            .body("name", equalTo("My App"))
            .body("requiresExplicitAccess", equalTo(false))
            .body("createdAt", notNullValue())
    }

    @Test
    fun `create app defaults requiresExplicitAccess to false`() {
        given()
            .header("X-Admin-Key", adminKey)
            .contentType(ContentType.JSON)
            .body("""{"id":"open-app","name":"Open App"}""")
        .`when`().post("/auth/apps")
        .then()
            .statusCode(201)
            .body("requiresExplicitAccess", equalTo(false))
    }

    @Test
    fun `create duplicate app returns 409`() {
        val body = """{"id":"dup-app","name":"Dup"}"""
        given().header("X-Admin-Key", adminKey).contentType(ContentType.JSON).body(body)
            .`when`().post("/auth/apps").then().statusCode(201)

        given()
            .header("X-Admin-Key", adminKey)
            .contentType(ContentType.JSON)
            .body(body)
        .`when`().post("/auth/apps")
        .then()
            .statusCode(409)
            .body("error", equalTo("conflict"))
    }

    @Test
    fun `list apps returns all registered apps`() {
        createApp("app-one", "App One")
        createApp("app-two", "App Two")

        given()
            .header("X-Admin-Key", adminKey)
        .`when`().get("/auth/apps")
        .then()
            .statusCode(200)
            .body("size()", equalTo(2))
    }

    @Test
    fun `list apps returns empty list when none registered`() {
        given()
            .header("X-Admin-Key", adminKey)
        .`when`().get("/auth/apps")
        .then()
            .statusCode(200)
            .body("size()", equalTo(0))
    }

    @Test
    fun `delete app returns 204`() {
        createApp("delete-me", "Delete Me")

        given()
            .header("X-Admin-Key", adminKey)
        .`when`().delete("/auth/apps/delete-me")
        .then()
            .statusCode(204)

        given()
            .header("X-Admin-Key", adminKey)
        .`when`().get("/auth/apps")
        .then()
            .statusCode(200)
            .body("size()", equalTo(0))
    }

    @Test
    fun `delete unknown app returns 404`() {
        given()
            .header("X-Admin-Key", adminKey)
        .`when`().delete("/auth/apps/nonexistent-app")
        .then()
            .statusCode(404)
            .body("error", equalTo("not_found"))
    }

    // ── Admin key validation ──────────────────────────────────────────────────

    @Test
    fun `missing admin key returns 401`() {
        given()
            .contentType(ContentType.JSON)
            .body("""{"id":"x","name":"X"}""")
        .`when`().post("/auth/apps")
        .then()
            .statusCode(401)
            .body("error", equalTo("unauthorized"))
    }

    @Test
    fun `wrong admin key returns 401`() {
        given()
            .header("X-Admin-Key", "wrong-key")
            .contentType(ContentType.JSON)
            .body("""{"id":"x","name":"X"}""")
        .`when`().post("/auth/apps")
        .then()
            .statusCode(401)
            .body("error", equalTo("unauthorized"))
    }

    // ── Per-app access management ─────────────────────────────────────────────

    @Test
    fun `list access returns empty for app with no grants`() {
        createApp("gated", "Gated", requiresExplicitAccess = true)

        given()
            .header("X-Admin-Key", adminKey)
        .`when`().get("/auth/apps/gated/access")
        .then()
            .statusCode(200)
            .body("size()", equalTo(0))
    }

    @Test
    fun `grant access then revoke then list is empty`() {
        createApp("managed", "Managed", requiresExplicitAccess = true)
        val userId = registerAndGetUserId("managed-user@example.com")

        given()
            .header("X-Admin-Key", adminKey)
            .contentType(ContentType.JSON)
        .`when`().post("/auth/apps/managed/access/$userId")
        .then()
            .statusCode(200)
            .body("userId", equalTo(userId))
            .body("appId", equalTo("managed"))
            .body("role", equalTo("user"))

        given()
            .header("X-Admin-Key", adminKey)
        .`when`().get("/auth/apps/managed/access")
        .then()
            .statusCode(200)
            .body("size()", equalTo(1))

        given()
            .header("X-Admin-Key", adminKey)
        .`when`().delete("/auth/apps/managed/access/$userId")
        .then()
            .statusCode(204)

        given()
            .header("X-Admin-Key", adminKey)
        .`when`().get("/auth/apps/managed/access")
        .then()
            .statusCode(200)
            .body("size()", equalTo(0))
    }

    @Test
    fun `grant with custom role is preserved`() {
        createApp("role-app", "Role App", requiresExplicitAccess = true)
        val userId = registerAndGetUserId("admin-user@example.com")

        given()
            .header("X-Admin-Key", adminKey)
            .contentType(ContentType.JSON)
            .body("""{"role":"admin"}""")
        .`when`().post("/auth/apps/role-app/access/$userId")
        .then()
            .statusCode(200)
            .body("role", equalTo("admin"))
    }

    // ── Per-app access gate (login flow) ──────────────────────────────────────

    @Test
    fun `register into gated app auto-grants access`() {
        createApp("private-app", "Private", requiresExplicitAccess = true)

        // Register with X-App-Id — should auto-grant and succeed
        given()
            .contentType(ContentType.JSON)
            .header("X-App-Id", "private-app")
            .body("""{"email":"newuser@example.com","password":"Str0ng!Pass42"}""")
        .`when`().post("/auth/register")
        .then()
            .statusCode(201)

        // Login should also succeed (has the auto-granted access)
        given()
            .contentType(ContentType.JSON)
            .header("X-App-Id", "private-app")
            .body("""{"email":"newuser@example.com","password":"Str0ng!Pass42"}""")
        .`when`().post("/auth/login")
        .then()
            .statusCode(200)
            .body("token", notNullValue())
    }

    @Test
    fun `login to gated app without grant returns 403`() {
        createApp("exclusive-app", "Exclusive", requiresExplicitAccess = true)

        // Register without X-App-Id — no auto-grant
        given()
            .contentType(ContentType.JSON)
            .body("""{"email":"outsider@example.com","password":"Str0ng!Pass42"}""")
        .`when`().post("/auth/register")
        .then()
            .statusCode(201)

        // Try to login with X-App-Id — should be denied
        given()
            .contentType(ContentType.JSON)
            .header("X-App-Id", "exclusive-app")
            .body("""{"email":"outsider@example.com","password":"Str0ng!Pass42"}""")
        .`when`().post("/auth/login")
        .then()
            .statusCode(403)
            .body("error", equalTo("forbidden"))
    }

    @Test
    fun `login to open app succeeds for any registered user`() {
        createApp("open-app", "Open", requiresExplicitAccess = false)

        given()
            .contentType(ContentType.JSON)
            .body("""{"email":"anyone@example.com","password":"Str0ng!Pass42"}""")
        .`when`().post("/auth/register")
        .then()
            .statusCode(201)

        given()
            .contentType(ContentType.JSON)
            .header("X-App-Id", "open-app")
            .body("""{"email":"anyone@example.com","password":"Str0ng!Pass42"}""")
        .`when`().post("/auth/login")
        .then()
            .statusCode(200)
    }

    @Test
    fun `login without X-App-Id skips app gate entirely`() {
        createApp("any-app", "Any", requiresExplicitAccess = true)

        given()
            .contentType(ContentType.JSON)
            .body("""{"email":"freeuser@example.com","password":"Str0ng!Pass42"}""")
        .`when`().post("/auth/register")
        .then()
            .statusCode(201)

        // No X-App-Id → gate is not checked → login succeeds
        given()
            .contentType(ContentType.JSON)
            .body("""{"email":"freeuser@example.com","password":"Str0ng!Pass42"}""")
        .`when`().post("/auth/login")
        .then()
            .statusCode(200)
    }

    @Test
    fun `grant to nonexistent user returns 404`() {
        createApp("test-app", "Test")

        given()
            .header("X-Admin-Key", adminKey)
            .contentType(ContentType.JSON)
        .`when`().post("/auth/apps/test-app/access/nonexistent-user-id")
        .then()
            .statusCode(404)
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private fun createApp(id: String, name: String, requiresExplicitAccess: Boolean = false) {
        given()
            .header("X-Admin-Key", adminKey)
            .contentType(ContentType.JSON)
            .body("""{"id":"$id","name":"$name","requiresExplicitAccess":$requiresExplicitAccess}""")
        .`when`().post("/auth/apps")
        .then()
            .statusCode(201)
    }

    private fun registerAndGetUserId(email: String): String {
        return given()
            .contentType(ContentType.JSON)
            .body("""{"email":"$email","password":"Str0ng!Pass42"}""")
        .`when`().post("/auth/register")
        .then()
            .statusCode(201)
            .extract().path("user.id")
    }
}
