package dev.vault.sdk.user

import com.google.gson.annotations.SerializedName
import java.util.Date

/**
 * Vault user model
 */
data class User(
    val id: String,
    val email: String,
    val emailVerified: Boolean,
    val name: String?,
    val avatar: String?,
    @SerializedName("created_at")
    val createdAt: Date,
    @SerializedName("updated_at")
    val updatedAt: Date,
    val metadata: Map<String, Any>? = null,
    val organizations: List<UserOrganization>? = null,
    val mfaEnabled: Boolean = false,
    val providers: List<String> = emptyList()
) {
    /**
     * User's display name (falls back to email if name is null)
     */
    val displayName: String
        get() = name ?: email.substringBefore("@")
    
    /**
     * Initials for avatar placeholder
     */
    val initials: String
        get() = displayName
            .split(" ")
            .take(2)
            .map { it.firstOrNull()?.uppercaseChar() ?: "" }
            .joinToString("")
}

/**
 * User organization membership
 */
data class UserOrganization(
    val id: String,
    val name: String,
    val slug: String,
    val role: OrganizationRole,
    val permissions: List<String>,
    @SerializedName("joined_at")
    val joinedAt: Date
)

/**
 * Organization roles
 */
enum class OrganizationRole {
    @SerializedName("owner")
    OWNER,
    @SerializedName("admin")
    ADMIN,
    @SerializedName("member")
    MEMBER,
    @SerializedName("guest")
    GUEST
}

/**
 * User profile for updates
 */
data class Profile(
    val name: String? = null,
    val avatar: String? = null,
    val metadata: Map<String, Any>? = null
) {
    /**
     * Create profile update request with only changed fields
     */
    fun toUpdateRequest(): Map<String, Any> {
        val map = mutableMapOf<String, Any>()
        name?.let { map["name"] = it }
        avatar?.let { map["avatar"] = it }
        metadata?.let { map["metadata"] = it }
        return map
    }
}

/**
 * User profile service
 */
class VaultUserProfile {
    
    private val apiClient = dev.vault.sdk.network.APIClient.instance
    
    /**
     * Get current user profile
     * 
     * @return Current user
     * @throws dev.vault.sdk.network.VaultException if request fails
     */
    suspend fun getCurrentUser(): User {
        return apiClient.get("/users/me")
    }
    
    /**
     * Update user profile
     * 
     * @param profile Profile updates
     * @return Updated user
     * @throws dev.vault.sdk.network.VaultException if request fails
     */
    suspend fun updateProfile(profile: Profile): User {
        return apiClient.patch(
            endpoint = "/users/me",
            body = profile.toUpdateRequest()
        )
    }
    
    /**
     * Update user email
     * 
     * @param newEmail New email address
     * @param password Current password for verification
     * @throws dev.vault.sdk.network.VaultException if request fails
     */
    suspend fun updateEmail(newEmail: String, password: String) {
        apiClient.post<Map<String, String>, Unit>(
            endpoint = "/users/me/email",
            body = mapOf(
                "email" to newEmail,
                "password" to password
            )
        )
    }
    
    /**
     * Change password
     * 
     * @param currentPassword Current password
     * @param newPassword New password
     * @param revokeOtherSessions Whether to sign out from other devices
     * @throws dev.vault.sdk.network.VaultException if request fails
     */
    suspend fun changePassword(
        currentPassword: String,
        newPassword: String,
        revokeOtherSessions: Boolean = false
    ) {
        apiClient.post<Map<String, Any>, Unit>(
            endpoint = "/users/me/password",
            body = mapOf(
                "current_password" to currentPassword,
                "new_password" to newPassword,
                "revoke_other_sessions" to revokeOtherSessions
            )
        )
    }
    
    /**
     * Upload avatar image
     * 
     * @param imageBytes Image data
     * @param contentType MIME type (e.g., "image/jpeg")
     * @return Updated user with new avatar URL
     * @throws dev.vault.sdk.network.VaultException if upload fails
     */
    suspend fun uploadAvatar(imageBytes: ByteArray, contentType: String): User {
        return apiClient.uploadFile(
            endpoint = "/users/me/avatar",
            fileBytes = imageBytes,
            contentType = contentType,
            fieldName = "avatar"
        )
    }
    
    /**
     * Delete user account permanently
     * 
     * @param password Current password for confirmation
     * @throws dev.vault.sdk.network.VaultException if deletion fails
     */
    suspend fun deleteAccount(password: String) {
        apiClient.post<Map<String, String>, Unit>(
            endpoint = "/users/me/delete",
            body = mapOf("password" to password)
        )
    }
    
    /**
     * Get active sessions
     * 
     * @return List of active sessions
     */
    suspend fun getSessions(): List<SessionInfo> {
        return apiClient.get("/users/me/sessions")
    }
    
    /**
     * Revoke a specific session
     * 
     * @param sessionId Session ID to revoke
     */
    suspend fun revokeSession(sessionId: String) {
        apiClient.delete("/users/me/sessions/$sessionId")
    }
}

/**
 * Session information
 */
data class SessionInfo(
    val id: String,
    @SerializedName("device_info")
    val deviceInfo: DeviceInfoSummary,
    val location: String?,
    @SerializedName("created_at")
    val createdAt: Date,
    @SerializedName("last_active_at")
    val lastActiveAt: Date,
    val isCurrent: Boolean
)

/**
 * Device info summary for sessions
 */
data class DeviceInfoSummary(
    val platform: String,
    val model: String,
    val osVersion: String,
    val appVersion: String
)
