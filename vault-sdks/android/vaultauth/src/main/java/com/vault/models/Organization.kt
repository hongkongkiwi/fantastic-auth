package com.vault.models

import com.google.gson.annotations.SerializedName
import java.util.Date

/**
 * Represents an organization in the Vault system
 */
data class Organization(
    val id: String,
    @SerializedName("tenant_id")
    val tenantId: String,
    val name: String,
    val slug: String,
    @SerializedName("logo_url")
    val logoUrl: String? = null,
    val description: String? = null,
    val website: String? = null,
    @SerializedName("max_members")
    val maxMembers: Int? = null,
    val role: OrganizationRole = OrganizationRole.MEMBER,
    @SerializedName("member_count")
    val memberCount: Int? = null,
    @SerializedName("created_at")
    val createdAt: Date = Date(),
    @SerializedName("updated_at")
    val updatedAt: Date = Date()
) {
    /**
     * Get the display name (name or slug fallback)
     */
    fun getDisplayName(): String = name

    /**
     * Check if user is an owner
     */
    fun isOwner(): Boolean = role == OrganizationRole.OWNER

    /**
     * Check if user is an admin or owner
     */
    fun isAdminOrOwner(): Boolean = role == OrganizationRole.OWNER || role == OrganizationRole.ADMIN
}

/**
 * Organization member
 */
data class OrganizationMember(
    val id: String,
    @SerializedName("user_id")
    val userId: String,
    val email: String,
    val name: String? = null,
    @SerializedName("avatar_url")
    val avatarUrl: String? = null,
    val role: OrganizationRole,
    val status: MemberStatus,
    @SerializedName("joined_at")
    val joinedAt: Date? = null
) {
    /**
     * Get member display name
     */
    fun getDisplayName(): String = name ?: email
}

/**
 * Member status
 */
enum class MemberStatus {
    @SerializedName("pending")
    PENDING,
    @SerializedName("active")
    ACTIVE,
    @SerializedName("suspended")
    SUSPENDED
}

/**
 * Create organization request
 */
internal data class CreateOrganizationRequest(
    val name: String,
    val slug: String? = null,
    val description: String? = null,
    val website: String? = null
)

/**
 * Update organization request
 */
internal data class UpdateOrganizationRequest(
    val name: String? = null,
    val slug: String? = null,
    val description: String? = null,
    val website: String? = null
)

/**
 * Switch organization request
 */
internal data class SwitchOrganizationRequest(
    @SerializedName("organization_id")
    val organizationId: String
)

/**
 * Invite member request
 */
internal data class InviteMemberRequest(
    val email: String,
    val role: OrganizationRole = OrganizationRole.MEMBER
)

/**
 * Update member role request
 */
internal data class UpdateMemberRoleRequest(
    val role: OrganizationRole
)

/**
 * Organization list response
 */
internal data class OrganizationListResponse(
    val organizations: List<Organization>,
    val total: Int,
    val page: Int,
    @SerializedName("per_page")
    val perPage: Int,
    @SerializedName("has_more")
    val hasMore: Boolean
)

/**
 * Member list response
 */
internal data class MemberListResponse(
    val members: List<OrganizationMember>
)

/**
 * Organization switch response
 */
internal data class OrganizationSwitchResponse(
    val organization: Organization,
    val session: Session
)
