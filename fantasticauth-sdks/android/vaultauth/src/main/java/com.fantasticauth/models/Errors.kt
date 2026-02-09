package com.vault.models

import com.google.gson.annotations.SerializedName
import java.io.IOException

/**
 * Exception thrown by VaultAuth SDK
 */
sealed class VaultAuthException(
    message: String,
    cause: Throwable? = null
) : Exception(message, cause) {

    /**
     * Configuration errors
     */
    class NotConfigured : VaultAuthException("VaultAuth has not been configured. Call configure() first.")
    
    class InvalidConfiguration(reason: String) : VaultAuthException("Invalid configuration: $reason")

    /**
     * Authentication errors
     */
    class InvalidCredentials : VaultAuthException("Invalid email or password.")
    
    class SessionExpired : VaultAuthException("Your session has expired. Please log in again.")
    
    class UserNotFound : VaultAuthException("User not found.")
    
    class AccountLocked : VaultAuthException("Account is locked. Please contact support.")
    
    class AccountNotVerified : VaultAuthException("Account is not verified. Please check your email.")

    /**
     * Token errors
     */
    class TokenNotFound : VaultAuthException("Authentication token not found.")
    
    class TokenInvalid : VaultAuthException("Authentication token is invalid.")
    
    class TokenRefreshFailed(cause: Throwable? = null) : 
        VaultAuthException("Failed to refresh session.", cause)

    /**
     * Network errors
     */
    class NetworkError(cause: Throwable) : 
        VaultAuthException("Network error: ${cause.message}", cause)
    
    class ServerError(val code: Int, message: String?) : 
        VaultAuthException("Server error ($code): ${message ?: "Unknown error"}")
    
    class DecodingError(cause: Throwable) : 
        VaultAuthException("Failed to decode response: ${cause.message}", cause)

    /**
     * Biometric errors
     */
    class BiometricNotAvailable : 
        VaultAuthException("Biometric authentication is not available on this device.")
    
    class BiometricNotEnrolled : 
        VaultAuthException("No biometric credentials are enrolled.")
    
    class BiometricFailed : 
        VaultAuthException("Biometric authentication failed.")
    
    class BiometricCancelled : 
        VaultAuthException("Biometric authentication was cancelled.")

    /**
     * MFA errors
     */
    class MfaRequired(val challenge: MfaChallenge) : 
        VaultAuthException("Multi-factor authentication is required.")
    
    class MfaInvalidCode : 
        VaultAuthException("Invalid MFA code. Please try again.")
    
    class MfaSetupFailed(message: String) : 
        VaultAuthException("Failed to set up MFA: $message")

    /**
     * OAuth errors
     */
    class OAuthCancelled : 
        VaultAuthException("OAuth authentication was cancelled.")
    
    class OAuthFailed(reason: String) : 
        VaultAuthException("OAuth authentication failed: $reason")

    /**
     * Organization errors
     */
    class OrganizationNotFound : 
        VaultAuthException("Organization not found.")
    
    class OrganizationSwitchFailed(cause: Throwable? = null) : 
        VaultAuthException("Failed to switch organization.", cause)

    /**
     * Unknown error
     */
    class Unknown(message: String) : VaultAuthException("Unknown error: $message")
}

/**
 * Check if the error is retryable
 */
fun VaultAuthException.isRetryable(): Boolean {
    return when (this) {
        is VaultAuthException.NetworkError,
        is VaultAuthException.ServerError -> true
        else -> false
    }
}

/**
 * API error response from server
 */
internal data class ApiErrorResponse(
    val error: String,
    val message: String? = null,
    val code: String? = null,
    val details: Map<String, Any>? = null
)

/**
 * Extension to convert API error response to exception
 */
internal fun ApiErrorResponse.toException(statusCode: Int): VaultAuthException {
    return when (code ?: error) {
        "invalid_credentials" -> VaultAuthException.InvalidCredentials()
        "session_expired" -> VaultAuthException.SessionExpired()
        "user_not_found" -> VaultAuthException.UserNotFound()
        "account_locked" -> VaultAuthException.AccountLocked()
        "account_not_verified" -> VaultAuthException.AccountNotVerified()
        "token_invalid" -> VaultAuthException.TokenInvalid()
        "token_refresh_failed" -> VaultAuthException.TokenRefreshFailed()
        "mfa_required" -> VaultAuthException.MfaRequired(
            MfaChallenge(MfaMethod.TOTP, java.util.Date(System.currentTimeMillis() + 300000))
        )
        "mfa_invalid_code" -> VaultAuthException.MfaInvalidCode()
        "organization_not_found" -> VaultAuthException.OrganizationNotFound()
        else -> VaultAuthException.ServerError(statusCode, message ?: error)
    }
}

/**
 * Keystore/storage errors
 */
internal sealed class StorageException(message: String) : Exception(message) {
    class ItemNotFound : StorageException("Storage item not found")
    class DuplicateItem : StorageException("Storage item already exists")
    class InvalidStatus(val status: Int) : StorageException("Storage error: $status")
    class ConversionFailed : StorageException("Failed to convert storage data")
    class EncryptionFailed(cause: Throwable) : StorageException("Encryption failed: ${cause.message}")
}
