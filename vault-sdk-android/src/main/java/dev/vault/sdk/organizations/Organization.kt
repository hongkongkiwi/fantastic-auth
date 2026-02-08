package dev.vault.sdk.organizations

import dev.vault.sdk.network.APIClient
import dev.vault.sdk.session.VaultSession
import dev.vault.sdk.session.withTokenRefresh
import dev.vault.sdk.user.User
import dev.vault.sdk.utils.VaultLogger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import java.util.Date

/**
 * Organization management for B2B features
 */
class VaultOrganizations {
    
    private val apiClient = APIClient.instance
    
    companion object {
        private val _activeOrganization = MutableStateFlow<Organization?>(null)
        
        /**
         * Currently active organization as StateFlow
         */
        val activeOrganizationFlow: StateFlow<Organization?> = _activeOrganization.asStateFlow()
        
        /**
         * Update the active organization
         */
        internal fun setActiveOrganization(org: Organization?) {
            _activeOrganization.value = org
        }
    }
    
    /**
     * Currently active organization
     */
    val activeOrganization: Organization?
        get() = _activeOrganization.value
    
    /**
     * List all organizations the current user belongs to
     * 
     * @return List of organizations
     */
    suspend fun list(): List<Organization> = withContext(Dispatchers.IO) {
        val response: OrganizationsResponse = apiClient.get("/organizations")
        response.organizations
    }
    
    /**
     * Get organization by ID
     * 
     * @param id Organization ID
     * @return Organization details
     */
    suspend fun get(id: String): Organization = withContext(Dispatchers.IO) {
        apiClient.get("/organizations/$id")
    }
    
    /**
     * Create a new organization
     * 
     * @param name Organization name
     * @param slug Unique slug (optional, auto-generated if not provided)
     * @param metadata Optional metadata
     * @return Created organization
     */
    suspend fun create(
        name: String,
        slug: String? = null,
        metadata: Map<String, Any>? = null
    ): Organization = withContext(Dispatchers.IO) {
        val request = CreateOrganizationRequest(
            name = name,
            slug = slug,
            metadata = metadata
        )
        
        apiClient.post<CreateOrganizationRequest, Organization>(
            endpoint = "/organizations",
            body = request
        ).also {
            VaultLogger.i("Created organization: ${it.id}")
        }
    }
    
    /**
     * Update organization
     * 
     * @param id Organization ID
     * @param name New name (optional)
     * @param metadata New metadata (optional)
     * @return Updated organization
     */
    suspend fun update(
        id: String,
        name: String? = null,
        metadata: Map<String, Any>? = null
    ): Organization = withContext(Dispatchers.IO) {
        val request = UpdateOrganizationRequest(
            name = name,
            metadata = metadata
        )
        
        apiClient.patch<UpdateOrganizationRequest, Organization>(
            endpoint = "/organizations/$id",
            body = request
        )
    }
    
    /**
     * Delete organization
     * 
     * @param id Organization ID
     */
    suspend fun delete(id: String) = withContext(Dispatchers.IO) {
        apiClient.delete("/organizations/$id")
        VaultLogger.i("Deleted organization: $id")
    }
    
    /**
     * Set the active organization
     * This affects API calls that are organization-scoped
     * 
     * @param id Organization ID or null to clear
     */
    suspend fun setActive(id: String?) = withContext(Dispatchers.IO) {
        if (id == null) {
            setActiveOrganization(null)
            apiClient.clearOrganizationId()
            VaultLogger.i("Cleared active organization")
        } else {
            val org = get(id)
            setActiveOrganization(org)
            apiClient.setOrganizationId(id)
            VaultLogger.i("Set active organization: $id")
        }
    }
    
    /**
     * Get members of an organization
     * 
     * @param orgId Organization ID
     * @return List of members
     */
    suspend fun getMembers(orgId: String): List<OrganizationMember> = withContext(Dispatchers.IO) {
        val response: MembersResponse = apiClient.get("/organizations/$orgId/members")
        response.members
    }
    
    /**
     * Invite a user to an organization
     * 
     * @param orgId Organization ID
     * @param email Email of user to invite
     * @param role Role to assign
     * @param metadata Optional metadata
     * @return Created invitation
     */
    suspend fun inviteMember(
        orgId: String,
        email: String,
        role: OrganizationRole = OrganizationRole.MEMBER,
        metadata: Map<String, Any>? = null
    ): Invitation = withContext(Dispatchers.IO) {
        val request = InviteMemberRequest(
            email = email,
            role = role,
            metadata = metadata
        )
        
        apiClient.post<InviteMemberRequest, Invitation>(
            endpoint = "/organizations/$orgId/invitations",
            body = request
        ).also {
            VaultLogger.i("Invited $email to organization $orgId")
        }
    }
    
    /**
     * Update member role
     * 
     * @param orgId Organization ID
     * @param userId User ID
     * @param newRole New role
     */
    suspend fun updateMemberRole(
        orgId: String,
        userId: String,
        newRole: OrganizationRole
    ) = withContext(Dispatchers.IO) {
        val request = UpdateRoleRequest(role = newRole)
        
        apiClient.patch<UpdateRoleRequest, Unit>(
            endpoint = "/organizations/$orgId/members/$userId",
            body = request
        )
    }
    
    /**
     * Remove member from organization
     * 
     * @param orgId Organization ID
     * @param userId User ID
     */
    suspend fun removeMember(orgId: String, userId: String) = withContext(Dispatchers.IO) {
        apiClient.delete("/organizations/$orgId/members/$userId")
        VaultLogger.i("Removed member $userId from organization $orgId")
    }
    
    /**
     * Accept an organization invitation
     * 
     * @param token Invitation token
     * @return The organization joined
     */
    suspend fun acceptInvitation(token: String): Organization = withContext(Dispatchers.IO) {
        val request = AcceptInvitationRequest(token = token)
        
        apiClient.post<AcceptInvitationRequest, Organization>(
            endpoint = "/organizations/invitations/accept",
            body = request
        ).also {
            VaultLogger.i("Accepted invitation to organization: ${it.id}")
        }
    }
    
    /**
     * Get pending invitations for an organization
     * 
     * @param orgId Organization ID
     * @return List of pending invitations
     */
    suspend fun getPendingInvitations(orgId: String): List<Invitation> = withContext(Dispatchers.IO) {
        val response: InvitationsResponse = apiClient.get("/organizations/$orgId/invitations")
        response.invitations.filter { it.status == InvitationStatus.PENDING }
    }
    
    /**
     * Cancel an invitation
     * 
     * @param orgId Organization ID
     * @param invitationId Invitation ID
     */
    suspend fun cancelInvitation(orgId: String, invitationId: String) = withContext(Dispatchers.IO) {
        apiClient.delete("/organizations/$orgId/invitations/$invitationId")
    }
    
    /**
     * Create API key for organization
     * 
     * @param orgId Organization ID
     * @param name Key name
     * @param permissions Optional permissions
     * @return Created API key (token only shown once)
     */
    suspend fun createApiKey(
        orgId: String,
        name: String,
        permissions: List<String>? = null
    ): ApiKey = withContext(Dispatchers.IO) {
        val request = CreateApiKeyRequest(
            name = name,
            permissions = permissions
        )
        
        apiClient.post<CreateApiKeyRequest, ApiKey>(
            endpoint = "/organizations/$orgId/api-keys",
            body = request
        )
    }
    
    /**
     * List organization API keys
     * 
     * @param orgId Organization ID
     * @return List of API keys (without tokens)
     */
    suspend fun listApiKeys(orgId: String): List<ApiKey> = withContext(Dispatchers.IO) {
        val response: ApiKeysResponse = apiClient.get("/organizations/$orgId/api-keys")
        response.keys
    }
    
    /**
     * Revoke an API key
     * 
     * @param orgId Organization ID
     * @param keyId API key ID
     */
    suspend fun revokeApiKey(orgId: String, keyId: String) = withContext(Dispatchers.IO) {
        apiClient.delete("/organizations/$orgId/api-keys/$keyId")
    }
    
    // Data classes
    
    private data class OrganizationsResponse(
        val organizations: List<Organization>
    )
    
    private data class CreateOrganizationRequest(
        val name: String,
        val slug: String?,
        val metadata: Map<String, Any>?
    )
    
    private data class UpdateOrganizationRequest(
        val name: String?,
        val metadata: Map<String, Any>?
    )
    
    private data class MembersResponse(
        val members: List<OrganizationMember>
    )
    
    private data class InviteMemberRequest(
        val email: String,
        val role: OrganizationRole,
        val metadata: Map<String, Any>?
    )
    
    private data class UpdateRoleRequest(
        val role: OrganizationRole
    )
    
    private data class AcceptInvitationRequest(
        val token: String
    )
    
    private data class InvitationsResponse(
        val invitations: List<Invitation>
    )
    
    private data class CreateApiKeyRequest(
        val name: String,
        val permissions: List<String>?
    )
    
    private data class ApiKeysResponse(
        val keys: List<ApiKey>
    )
}

/**
 * Organization model
 */
data class Organization(
    val id: String,
    val name: String,
    val slug: String,
    val ownerId: String,
    val metadata: Map<String, Any>?,
    val createdAt: Date,
    val updatedAt: Date
)

/**
 * Organization role
 */
enum class OrganizationRole {
    OWNER,
    ADMIN,
    MEMBER,
    GUEST
}

/**
 * Organization member
 */
data class OrganizationMember(
    val id: String,
    val user: User,
    val role: OrganizationRole,
    val permissions: List<String>,
    val joinedAt: Date
)

/**
 * Invitation model
 */
data class Invitation(
    val id: String,
    val email: String,
    val role: OrganizationRole,
    val status: InvitationStatus,
    val invitedBy: User,
    val organizationId: String,
    val expiresAt: Date,
    val createdAt: Date
)

/**
 * Invitation status
 */
enum class InvitationStatus {
    PENDING,
    ACCEPTED,
    DECLINED,
    EXPIRED,
    CANCELLED
}

/**
 * API key model
 */
data class ApiKey(
    val id: String,
    val name: String,
    val permissions: List<String>?,
    val token: String?, // Only present on creation
    val lastUsedAt: Date?,
    val createdAt: Date
)
