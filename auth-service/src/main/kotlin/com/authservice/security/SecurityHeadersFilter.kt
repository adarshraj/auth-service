package com.authservice.security

import jakarta.ws.rs.container.ContainerRequestContext
import jakarta.ws.rs.container.ContainerResponseContext
import jakarta.ws.rs.container.ContainerResponseFilter
import jakarta.ws.rs.ext.Provider

/** Adds standard security headers to all responses. */
@Provider
class SecurityHeadersFilter : ContainerResponseFilter {

    override fun filter(request: ContainerRequestContext, response: ContainerResponseContext) {
        val headers = response.headers
        headers.putSingle("X-Content-Type-Options", "nosniff")
        headers.putSingle("X-Frame-Options", "DENY")
        headers.putSingle("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        headers.putSingle("Referrer-Policy", "strict-origin-when-cross-origin")
        headers.putSingle("X-XSS-Protection", "0") // Disabled per modern best practice (CSP supersedes)
        // HSTS — only effective over HTTPS; harmless over HTTP (browsers ignore it)
        headers.putSingle("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    }
}
