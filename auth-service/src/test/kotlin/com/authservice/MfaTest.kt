package com.authservice

import com.authservice.domain.UserRepository
import com.authservice.service.TotpService
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
class MfaTest {

    @Inject lateinit var userRepository: UserRepository
    @Inject lateinit var totpService: TotpService

    @BeforeEach
    @Transactional
    fun cleanup() {
        userRepository.deleteAll()
    }

    private fun registerAndGetToken(): String {
        return given()
            .contentType(ContentType.JSON)
            .body("""{"email":"mfa@example.com","password":"password123"}""")
            .`when`().post("/auth/register")
            .then().statusCode(201)
            .extract().path("token")
    }

    // ── MFA Setup ────────────────────────────────────────────────────────────

    @Test
    fun `mfa setup returns secret and otpauth URI`() {
        val token = registerAndGetToken()
        given()
            .contentType(ContentType.JSON)
            .header("Authorization", "Bearer $token")
            .`when`().post("/auth/mfa/setup")
            .then()
            .statusCode(200)
            .body("secret", notNullValue())
            .body("otpauthUri", notNullValue())
            .body("recoveryCodes.size()", equalTo(8))
    }

    @Test
    fun `mfa setup requires auth`() {
        given()
            .contentType(ContentType.JSON)
            .`when`().post("/auth/mfa/setup")
            .then()
            .statusCode(401)
    }

    // ── MFA Confirm ──────────────────────────────────────────────────────────

    @Test
    fun `mfa confirm with valid TOTP enables MFA`() {
        val token = registerAndGetToken()

        // Setup MFA
        val secret: String = given()
            .contentType(ContentType.JSON)
            .header("Authorization", "Bearer $token")
            .`when`().post("/auth/mfa/setup")
            .then().statusCode(200)
            .extract().path("secret")

        // Generate a valid TOTP code
        val code = generateValidCode(secret)

        // Confirm MFA
        given()
            .contentType(ContentType.JSON)
            .header("Authorization", "Bearer $token")
            .body("""{"code":"$code"}""")
            .`when`().post("/auth/mfa/confirm")
            .then()
            .statusCode(200)
            .body("message", equalTo("MFA enabled"))
    }

    @Test
    fun `mfa confirm with invalid code fails`() {
        val token = registerAndGetToken()

        given()
            .contentType(ContentType.JSON)
            .header("Authorization", "Bearer $token")
            .`when`().post("/auth/mfa/setup")
            .then().statusCode(200)

        given()
            .contentType(ContentType.JSON)
            .header("Authorization", "Bearer $token")
            .body("""{"code":"000000"}""")
            .`when`().post("/auth/mfa/confirm")
            .then()
            .statusCode(400)
    }

    // ── Login with MFA ───────────────────────────────────────────────────────

    @Test
    fun `login returns mfa challenge when MFA is enabled`() {
        val token = registerAndGetToken()
        val secret = setupAndConfirmMfa(token)

        // Login should return MFA challenge, not a JWT
        given()
            .contentType(ContentType.JSON)
            .body("""{"email":"mfa@example.com","password":"password123"}""")
            .`when`().post("/auth/login")
            .then()
            .statusCode(200)
            .body("mfaRequired", equalTo(true))
            .body("mfaToken", notNullValue())
    }

    @Test
    fun `mfa verify with valid TOTP completes login`() {
        val token = registerAndGetToken()
        val secret = setupAndConfirmMfa(token)

        // Login to get MFA challenge
        val mfaToken: String = given()
            .contentType(ContentType.JSON)
            .body("""{"email":"mfa@example.com","password":"password123"}""")
            .`when`().post("/auth/login")
            .then().statusCode(200)
            .extract().path("mfaToken")

        val code = generateValidCode(secret)

        // Verify MFA
        given()
            .contentType(ContentType.JSON)
            .body("""{"mfaToken":"$mfaToken","code":"$code"}""")
            .`when`().post("/auth/mfa/verify")
            .then()
            .statusCode(200)
            .body("token", notNullValue())
            .body("user.email", equalTo("mfa@example.com"))
    }

    @Test
    fun `mfa verify with invalid code fails`() {
        val token = registerAndGetToken()
        setupAndConfirmMfa(token)

        val mfaToken: String = given()
            .contentType(ContentType.JSON)
            .body("""{"email":"mfa@example.com","password":"password123"}""")
            .`when`().post("/auth/login")
            .then().statusCode(200)
            .extract().path("mfaToken")

        given()
            .contentType(ContentType.JSON)
            .body("""{"mfaToken":"$mfaToken","code":"000000"}""")
            .`when`().post("/auth/mfa/verify")
            .then()
            .statusCode(401)
    }

    // ── Backup codes ─────────────────────────────────────────────────────────

    @Test
    fun `mfa verify with backup code completes login`() {
        val token = registerAndGetToken()
        val (_, recoveryCodes) = setupAndConfirmMfaWithCodes(token)

        val mfaToken: String = given()
            .contentType(ContentType.JSON)
            .body("""{"email":"mfa@example.com","password":"password123"}""")
            .`when`().post("/auth/login")
            .then().statusCode(200)
            .extract().path("mfaToken")

        given()
            .contentType(ContentType.JSON)
            .body("""{"mfaToken":"$mfaToken","code":"${recoveryCodes[0]}"}""")
            .`when`().post("/auth/mfa/verify")
            .then()
            .statusCode(200)
            .body("token", notNullValue())
    }

    @Test
    fun `backup code can only be used once`() {
        val token = registerAndGetToken()
        val (_, recoveryCodes) = setupAndConfirmMfaWithCodes(token)
        val backupCode = recoveryCodes[0]

        // First use — succeeds
        val mfaToken1: String = given()
            .contentType(ContentType.JSON)
            .body("""{"email":"mfa@example.com","password":"password123"}""")
            .`when`().post("/auth/login")
            .then().statusCode(200)
            .extract().path("mfaToken")

        given()
            .contentType(ContentType.JSON)
            .body("""{"mfaToken":"$mfaToken1","code":"$backupCode"}""")
            .`when`().post("/auth/mfa/verify")
            .then().statusCode(200)

        // Second use — fails
        val mfaToken2: String = given()
            .contentType(ContentType.JSON)
            .body("""{"email":"mfa@example.com","password":"password123"}""")
            .`when`().post("/auth/login")
            .then().statusCode(200)
            .extract().path("mfaToken")

        given()
            .contentType(ContentType.JSON)
            .body("""{"mfaToken":"$mfaToken2","code":"$backupCode"}""")
            .`when`().post("/auth/mfa/verify")
            .then().statusCode(401)
    }

    // ── Disable MFA ──────────────────────────────────────────────────────────

    @Test
    fun `disable MFA with valid TOTP succeeds`() {
        val token = registerAndGetToken()
        val secret = setupAndConfirmMfa(token)
        val code = generateValidCode(secret)

        given()
            .contentType(ContentType.JSON)
            .header("Authorization", "Bearer $token")
            .body("""{"code":"$code"}""")
            .`when`().post("/auth/mfa/disable")
            .then()
            .statusCode(200)
            .body("message", equalTo("MFA disabled"))

        // Login should now return a JWT directly, no MFA challenge
        given()
            .contentType(ContentType.JSON)
            .body("""{"email":"mfa@example.com","password":"password123"}""")
            .`when`().post("/auth/login")
            .then()
            .statusCode(200)
            .body("token", notNullValue())
    }

    // ── Login without MFA is unchanged ───────────────────────────────────────

    @Test
    fun `login without MFA returns token directly`() {
        registerAndGetToken()

        given()
            .contentType(ContentType.JSON)
            .body("""{"email":"mfa@example.com","password":"password123"}""")
            .`when`().post("/auth/login")
            .then()
            .statusCode(200)
            .body("token", notNullValue())
            .body("user.email", equalTo("mfa@example.com"))
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private fun setupAndConfirmMfa(authToken: String): String {
        return setupAndConfirmMfaWithCodes(authToken).first
    }

    private fun setupAndConfirmMfaWithCodes(authToken: String): Pair<String, List<String>> {
        val setupResponse = given()
            .contentType(ContentType.JSON)
            .header("Authorization", "Bearer $authToken")
            .`when`().post("/auth/mfa/setup")
            .then().statusCode(200)
            .extract()

        val secret: String = setupResponse.path("secret")
        val recoveryCodes: List<String> = setupResponse.path("recoveryCodes")

        val code = generateValidCode(secret)

        given()
            .contentType(ContentType.JSON)
            .header("Authorization", "Bearer $authToken")
            .body("""{"code":"$code"}""")
            .`when`().post("/auth/mfa/confirm")
            .then().statusCode(200)

        return Pair(secret, recoveryCodes)
    }

    /**
     * Generate a valid TOTP code for testing by using the TotpService internals.
     * We use reflection to call the private generateCode method to get a deterministic code.
     */
    private fun generateValidCode(secret: String): String {
        // Decode the base32 secret and generate code for current time step
        val base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        val data = secret.uppercase()
        val output = mutableListOf<Byte>()
        var buffer = 0
        var bitsLeft = 0
        for (ch in data) {
            val value = base32Chars.indexOf(ch)
            if (value < 0) continue
            buffer = (buffer shl 5) or value
            bitsLeft += 5
            if (bitsLeft >= 8) {
                bitsLeft -= 8
                output.add((buffer shr bitsLeft).toByte())
            }
        }
        val secretBytes = output.toByteArray()
        val timeStep = System.currentTimeMillis() / 1000 / 30

        val timeData = java.nio.ByteBuffer.allocate(8).putLong(timeStep).array()
        val mac = javax.crypto.Mac.getInstance("HmacSHA1")
        mac.init(javax.crypto.spec.SecretKeySpec(secretBytes, "HmacSHA1"))
        val hash = mac.doFinal(timeData)

        val offset = hash[hash.size - 1].toInt() and 0x0F
        val binary = ((hash[offset].toInt() and 0x7F) shl 24) or
            ((hash[offset + 1].toInt() and 0xFF) shl 16) or
            ((hash[offset + 2].toInt() and 0xFF) shl 8) or
            (hash[offset + 3].toInt() and 0xFF)

        val otp = binary % 1_000_000
        return otp.toString().padStart(6, '0')
    }
}
