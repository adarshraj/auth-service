package com.authservice.api

import com.authservice.service.EcKeyService
import jakarta.inject.Inject
import jakarta.ws.rs.GET
import jakarta.ws.rs.Path
import jakarta.ws.rs.Produces
import jakarta.ws.rs.core.MediaType
import org.eclipse.microprofile.openapi.annotations.Operation
import org.eclipse.microprofile.openapi.annotations.tags.Tag

@Path("/.well-known")
@Produces(MediaType.APPLICATION_JSON)
@Tag(name = "well-known", description = "Standard discovery endpoints")
class WellKnownResource @Inject constructor(
    private val ecKeyService: EcKeyService,
) {
    @GET
    @Path("/jwks.json")
    @Operation(summary = "JSON Web Key Set — public key for ES256 JWT verification")
    fun jwks(): Map<String, Any> = mapOf("keys" to listOf(ecKeyService.publicKeyAsJwk()))
}
