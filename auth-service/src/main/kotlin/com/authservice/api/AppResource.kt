package com.authservice.api

import com.authservice.api.dto.AccessResponse
import com.authservice.api.dto.AppResponse
import com.authservice.api.dto.CreateAppRequest
import com.authservice.api.dto.GrantAccessRequest
import com.authservice.domain.AppEntity
import com.authservice.domain.AppRepository
import com.authservice.domain.UserAppAccessEntity
import com.authservice.security.ApiKeyHasher
import com.authservice.service.UserService
import jakarta.inject.Inject
import jakarta.transaction.Transactional
import jakarta.validation.Valid
import jakarta.ws.rs.Consumes
import jakarta.ws.rs.DELETE
import jakarta.ws.rs.GET
import jakarta.ws.rs.HeaderParam
import jakarta.ws.rs.NotAuthorizedException
import jakarta.ws.rs.NotSupportedException
import jakarta.ws.rs.POST
import jakarta.ws.rs.Path
import jakarta.ws.rs.PathParam
import jakarta.ws.rs.Produces
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import org.eclipse.microprofile.config.inject.ConfigProperty
import org.eclipse.microprofile.openapi.annotations.Operation
import org.eclipse.microprofile.openapi.annotations.tags.Tag
import org.jboss.logging.Logger
import java.time.Instant
import java.util.Optional

@Path("/auth/apps")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
@Tag(name = "apps", description = "App registration and user access management (requires X-Admin-Key)")
class AppResource @Inject constructor(
    private val appRepository: AppRepository,
    private val userService: UserService,
    private val hasher: ApiKeyHasher,
    @ConfigProperty(name = "auth.admin-key") private val adminKey: Optional<String>,
) {
    companion object {
        private val log: Logger = Logger.getLogger(AppResource::class.java)
    }

    // ── App CRUD ──────────────────────────────────────────────────────────────

    @POST
    @Transactional
    @Operation(summary = "Register a new app")
    fun createApp(
        @HeaderParam("X-Admin-Key") key: String?,
        @Valid body: CreateAppRequest,
    ): Response {
        checkAdmin(key)
        if (appRepository.findById(body.id) != null) {
            return Response.status(409).entity(mapOf("error" to "conflict", "message" to "App '${body.id}' already exists")).build()
        }
        val app = AppEntity().apply {
            id = body.id
            name = body.name
            requiresExplicitAccess = body.requiresExplicitAccess
            createdAt = Instant.now()
        }
        appRepository.persist(app)
        log.infof("Registered app id=%s name=%s requiresExplicitAccess=%s", app.id, app.name, app.requiresExplicitAccess)
        return Response.status(201).entity(app.toResponse()).build()
    }

    @GET
    @Operation(summary = "List all registered apps")
    fun listApps(@HeaderParam("X-Admin-Key") key: String?): List<AppResponse> {
        checkAdmin(key)
        return appRepository.listAll().map { it.toResponse() }
    }

    @DELETE
    @Path("/{id}")
    @Transactional
    @Operation(summary = "Delete an app (does not delete users)")
    fun deleteApp(
        @HeaderParam("X-Admin-Key") key: String?,
        @PathParam("id") id: String,
    ): Response {
        checkAdmin(key)
        val app = appRepository.findById(id)
            ?: return Response.status(404).entity(mapOf("error" to "not_found", "message" to "App not found")).build()
        appRepository.delete(app)
        log.infof("Deleted app id=%s", id)
        return Response.noContent().build()
    }

    // ── Per-app access management ─────────────────────────────────────────────

    @GET
    @Path("/{appId}/access")
    @Operation(summary = "List users with explicit access to an app")
    fun listAccess(
        @HeaderParam("X-Admin-Key") key: String?,
        @PathParam("appId") appId: String,
    ): List<AccessResponse> {
        checkAdmin(key)
        return userService.listAccessByApp(appId).map { it.toResponse() }
    }

    @POST
    @Path("/{appId}/access/{userId}")
    @Transactional
    @Operation(summary = "Grant a user access to an app")
    fun grantAccess(
        @HeaderParam("X-Admin-Key") key: String?,
        @PathParam("appId") appId: String,
        @PathParam("userId") userId: String,
        body: GrantAccessRequest?,
    ): Response {
        checkAdmin(key)
        userService.grantAccess(userId, appId, body?.role ?: "user")
        log.infof("Granted access userId=%s appId=%s role=%s", userId, appId, body?.role ?: "user")
        return Response.ok(mapOf("userId" to userId, "appId" to appId, "role" to (body?.role ?: "user"))).build()
    }

    @DELETE
    @Path("/{appId}/access/{userId}")
    @Transactional
    @Operation(summary = "Revoke a user's access to an app")
    fun revokeAccess(
        @HeaderParam("X-Admin-Key") key: String?,
        @PathParam("appId") appId: String,
        @PathParam("userId") userId: String,
    ): Response {
        checkAdmin(key)
        userService.revokeAccess(userId, appId)
        log.infof("Revoked access userId=%s appId=%s", userId, appId)
        return Response.noContent().build()
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private fun checkAdmin(provided: String?) {
        val configured = adminKey.orElse(null)?.takeIf { it.isNotBlank() }
            ?: throw NotSupportedException("Admin API is disabled — set AUTH_ADMIN_KEY to enable it")
        if (provided.isNullOrBlank()) throw NotAuthorizedException("Missing X-Admin-Key", "Admin")
        if (!hasher.verify(provided, hasher.hash(configured))) {
            throw NotAuthorizedException("Invalid X-Admin-Key", "Admin")
        }
    }

    private fun AppEntity.toResponse() = AppResponse(
        id = id,
        name = name,
        requiresExplicitAccess = requiresExplicitAccess,
        createdAt = createdAt.toString(),
    )

    private fun UserAppAccessEntity.toResponse() = AccessResponse(
        userId = id.userId,
        appId = id.appId,
        role = role,
        grantedAt = grantedAt.toString(),
    )
}
