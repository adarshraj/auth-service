package com.authservice.api

import jakarta.validation.ConstraintViolationException
import jakarta.ws.rs.Priorities
import jakarta.ws.rs.WebApplicationException
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import jakarta.ws.rs.ext.ExceptionMapper
import jakarta.ws.rs.ext.Provider
import org.jboss.logging.Logger

@Provider
@jakarta.annotation.Priority(Priorities.USER + 100)
class WebApplicationExceptionMapper : ExceptionMapper<WebApplicationException> {

    companion object {
        private val log: Logger = Logger.getLogger(WebApplicationExceptionMapper::class.java)
    }

    override fun toResponse(exception: WebApplicationException): Response {
        val r = exception.response
        val status = r.status
        val rawMessage = exception.message?.takeIf { it.isNotBlank() } ?: r.statusInfo.reasonPhrase
        if (status >= 500) log.warnf(exception, "HTTP %d: %s", status, rawMessage)
        // Never forward internal details for 5xx — log them server-side only
        val clientMessage = if (status >= 500) "An internal error occurred" else rawMessage
        return json(status, errorCode(status), clientMessage)
    }
}

@Provider
@jakarta.annotation.Priority(Priorities.USER + 100)
class ConstraintViolationExceptionMapper : ExceptionMapper<ConstraintViolationException> {
    override fun toResponse(exception: ConstraintViolationException): Response {
        val msg = exception.constraintViolations.joinToString("; ") { "${it.propertyPath}: ${it.message}" }
        return json(400, "validation_error", msg)
    }
}

private fun errorCode(status: Int): String = when (status) {
    400 -> "bad_request"
    401 -> "unauthorized"
    403 -> "forbidden"
    404 -> "not_found"
    409 -> "conflict"
    429 -> "too_many_requests"
    in 500..599 -> "internal_error"
    else -> "http_$status"
}

private fun json(status: Int, error: String, message: String): Response =
    Response.status(status)
        .type(MediaType.APPLICATION_JSON)
        .entity(mapOf("error" to error, "message" to message, "status" to status))
        .build()
