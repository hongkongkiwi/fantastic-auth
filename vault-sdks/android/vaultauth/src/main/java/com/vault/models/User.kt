package com.vault.models

import com.google.gson.annotations.SerializedName
import java.util.Date

/**
 * Represents the status of a user account
 */
enum class UserStatus {
    @SerializedName("pending")
    PENDING,
    @SerializedName("active")
    ACTIVE,
    @SerializedName("suspended")
    SUSPENDED,
    @SerializedName("deactivated")
    DEACTIVATED
}

/**
 * Represents a user in the Vault system
 */
data class User(
    val id: String,
    @SerializedName("tenant_id")
    val tenantId: String,
    val email: String,
    @SerializedName("email_verified")
    val emailVerified: Boolean,
    val status: UserStatus,
    val profile: UserProfile,
    @SerializedName("mfa_enabled")
    val mfaEnabled: Boolean,
    @SerializedName("mfa_methods")
    val mfaMethods: List<MfaMethod> = emptyList(),
    val roles: List<String> = emptyList(),
    val permissions: List<String> = emptyList(),
    @SerializedName("last_login_at")
    val lastLoginAt: Date? = null,
    @SerializedName("created_at")
    val createdAt: Date = Date(),
    @SerializedName("updated_at")
    val updatedAt: Date = Date()
) {
    /**
     * Get the user's full name
     */
    fun getFullName(): String {
        return profile.name ?: profile.givenName?.let { given ->
            profile.familyName?.let { family ->
                "$given $family"
            } ?: given
        } ?: profile.familyName ?: email
    }

    /**
     * Check if user has a specific role
     */
    fun hasRole(role: String): Boolean = roles.contains(role)

    /**
     * Check if user has a specific permission
     */
    fun hasPermission(permission: String): Boolean = permissions.contains(permission)
}

/**
 * User profile information
 */
data class UserProfile(
    val name: String? = null,
    @SerializedName("given_name")
    val givenName: String? = null,
    @SerializedName("family_name")
    val familyName: String? = null,
    val picture: String? = null,
    @SerializedName("phone_number")
    val phoneNumber: String? = null,
    val metadata: Map<String, String>? = null
)

/**
 * MFA method types
 */
enum class MfaMethod {
    @SerializedName("totp")
    TOTP,
    @SerializedName("email")
    EMAIL,
    @SerializedName("sms")
    SMS,
    @SerializedName("webauthn")
    WEBAUTHN,
    @SerializedName("backup_codes")
    BACKUP_CODES
}

/**
 * Organization role types
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
 * OAuth provider types
 */
enum class OAuthProvider {
    GOOGLE,
    GITHUB,
    MICROSOFT,
    APPLE,
    CUSTOM
}

/**
 * Login request payload
 */
internal data class LoginRequest(
    val email: String,
    val password: String,
    @SerializedName("tenant_id")
    val tenantId: String? = null
)

/**
 * Signup request payload
 */
internal data class SignupRequest(
    val email: String,
    val password: String,
    val name: String? = null,
    @SerializedName("tenant_id")
    val tenantId: String? = null
)

/**
 * Token verification request
 */
internal data class TokenVerificationRequest(
    val token: String
)

/**
 * Auth response from server
 */
internal data class AuthResponse(
    val user: User,
    val session: Session
)

/**
 * User update request
 */
data class UserUpdateRequest(
    val name: String? = null,
    val email: String? = null,
    val metadata: Map<String, String>? = null
)

/**
 * Password change request
 */
data class PasswordChangeRequest(
    @SerializedName("current_password")
    val currentPassword: String,
    @SerializedName("new_password")
    val newPassword: String
)
