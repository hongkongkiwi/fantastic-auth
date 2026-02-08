package com.vault.models

import com.google.gson.annotations.SerializedName
import java.util.Date

/**
 * Represents an authenticated session
 */
data class Session(
    val id: String,
    @SerializedName("access_token")
    val accessToken: String,
    @SerializedName("refresh_token")
    val refreshToken: String,
    @SerializedName("expires_at")
    val expiresAt: Date,
    val user: User
) {
    /**
     * Check if the session is expired
     */
    fun isExpired(): Boolean {
        return Date().after(expiresAt)
    }

    /**
     * Check if the session will expire within the given buffer (in seconds)
     */
    fun willExpireWithin(bufferSeconds: Int = 300): Boolean {
        val bufferMs = bufferSeconds * 1000L
        return Date().time + bufferMs >= expiresAt.time
    }
}

/**
 * Session information for session management
 */
data class SessionInfo(
    val id: String,
    @SerializedName("user_id")
    val userId: String,
    @SerializedName("user_agent")
    val userAgent: String? = null,
    @SerializedName("ip_address")
    val ipAddress: String? = null,
    val location: String? = null,
    @SerializedName("created_at")
    val createdAt: Date = Date(),
    @SerializedName("last_active_at")
    val lastActiveAt: Date = Date(),
    @SerializedName("expires_at")
    val expiresAt: Date,
    @SerializedName("is_current")
    val isCurrent: Boolean = false
) {
    /**
     * Check if the session is active
     */
    fun isActive(): Boolean {
        return Date().before(expiresAt)
    }

    /**
     * Get a display-friendly location or fallback
     */
    fun getDisplayLocation(): String {
        return location ?: ipAddress ?: "Unknown location"
    }
}

/**
 * Token refresh request
 */
internal data class TokenRefreshRequest(
    @SerializedName("refresh_token")
    val refreshToken: String
)

/**
 * Token refresh response
 */
internal data class TokenRefreshResponse(
    @SerializedName("access_token")
    val accessToken: String,
    @SerializedName("refresh_token")
    val refreshToken: String? = null,
    @SerializedName("expires_at")
    val expiresAt: Date
)

/**
 * MFA challenge information
 */
data class MfaChallenge(
    val method: MfaMethod,
    @SerializedName("expires_at")
    val expiresAt: Date
) {
    /**
     * Check if the challenge is expired
     */
    fun isExpired(): Boolean {
        return Date().after(expiresAt)
    }
}

/**
 * MFA verification request
 */
internal data class MfaVerifyRequest(
    val code: String,
    val method: MfaMethod,
    @SerializedName("session_token")
    val sessionToken: String? = null
)

/**
 * MFA setup response
 */
data class MfaSetup(
    val secret: String,
    @SerializedName("qr_code")
    val qrCode: String,
    @SerializedName("backup_codes")
    val backupCodes: List<String>
)

/**
 * TOTP setup request
 */
internal data class TotpSetupRequest(
    val method: String = "totp"
)

/**
 * Enable MFA request
 */
internal data class EnableMfaRequest(
    val method: MfaMethod,
    val code: String? = null
)
