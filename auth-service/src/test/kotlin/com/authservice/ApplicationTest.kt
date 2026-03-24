package com.authservice

import io.quarkus.test.junit.QuarkusTest
import io.restassured.RestAssured.given
import org.junit.jupiter.api.Test

@QuarkusTest
class ApplicationTest {

    @Test
    fun `health endpoint returns UP`() {
        given()
        .`when`().get("/q/health")
        .then()
            .statusCode(200)
    }

    @Test
    fun `readiness probe returns UP`() {
        given()
        .`when`().get("/q/health/ready")
        .then()
            .statusCode(200)
    }

    @Test
    fun `liveness probe returns UP`() {
        given()
        .`when`().get("/q/health/live")
        .then()
            .statusCode(200)
    }
}
