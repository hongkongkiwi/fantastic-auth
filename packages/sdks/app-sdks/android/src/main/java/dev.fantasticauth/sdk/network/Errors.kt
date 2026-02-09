package dev.vault.sdk.network

/**
 * Base exception for Vault SDK errors
 */
open class VaultException(
    val code: String,
    message: String,
    val statusCode: Int? = null,
    cause: Throwable? = null
) : Exception(message, cause) {
    
    /**
     * Check if this is an authentication error
     */
    val isAuthError: Boolean
        get() = code in AUTH_ERROR_CODES || statusCode == 401
    
    /**
     * Check if this is a network error
     */
    val isNetworkError: Boolean
        get() = code == "network_error"
    
    /**
     * Check if this is a rate limit error
     */
    val isRateLimitError: Boolean
        get() = code == "rate_limit_exceeded" || statusCode == 429
    
    /**
     * Check if this is a not found error
     */
    val isNotFoundError: Boolean
        get() = code == "not_found" || statusCode == 404
    
    /**
     * Check if this is a validation error
     */
    val isValidationError: Boolean
        get() = code == "validation_error" || statusCode == 422
    
    companion object {
        private val AUTH_ERROR_CODES = setOf(
            "unauthorized",
            "token_expired",
            "invalid_token",
            "invalid_credentials",
            "session_expired",
            "account_disabled"
        )
    }
}

/**
 * Authentication specific exception
 */
class AuthException(
    code: String,
    message: String,
    statusCode: Int? = null,
    cause: Throwable? = null
) : VaultException(code, message, statusCode, cause)

/**
 * Network specific exception
 */
class NetworkException(
    message: String,
    cause: Throwable? = null
) : VaultException("network_error", message, null, cause)

/**
 * Validation specific exception with field errors
 */
class ValidationException(
    message: String,
    val fieldErrors: Map<String, List<String>> = emptyMap(),
    cause: Throwable? = null
) : VaultException("validation_error", message, 422, cause)

/**
 * Rate limit exception with retry information
 */
class RateLimitException(
    message: String = "Rate limit exceeded",
    val retryAfter: Int? = null,
    cause: Throwable? = null
) : VaultException("rate_limit_exceeded", message, 429, cause)

/**
 * Error codes used by Vault API
 */
object ErrorCodes {
    // Authentication errors
    const val UNAUTHORIZED = "unauthorized"
    const val INVALID_CREDENTIALS = "invalid_credentials"
    const val TOKEN_EXPIRED = "token_expired"
    const val INVALID_TOKEN = "invalid_token"
    const val SESSION_EXPIRED = "session_expired"
    const val ACCOUNT_DISABLED = "account_disabled"
    const val EMAIL_NOT_VERIFIED = "email_not_verified"
    const val MFA_REQUIRED = "mfa_required"
    const val MFA_INVALID = "mfa_invalid"
    
    // Resource errors
    const val NOT_FOUND = "not_found"
    const val ALREADY_EXISTS = "already_exists"
    const val CONFLICT = "conflict"
    
    // Validation errors
    const val VALIDATION_ERROR = "validation_error"
    const val INVALID_FORMAT = "invalid_format"
    const val REQUIRED_FIELD = "required_field"
    const val INVALID_VALUE = "invalid_value"
    
    // Rate limiting
    const val RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    
    // Organization errors
    const val ORG_NOT_FOUND = "organization_not_found"
    const val INSUFFICIENT_PERMISSIONS = "insufficient_permissions"
    const val MEMBER_NOT_FOUND = "member_not_found"
    const val INVITATION_EXPIRED = "invitation_expired"
    
    // Biometric errors
    const val BIOMETRIC_NOT_AVAILABLE = "biometric_not_available"
    const val BIOMETRIC_NOT_ENROLLED = "biometric_not_enrolled"
    const val BIOMETRIC_CANCELLED = "biometric_cancelled"
    const val BIOMETRIC_FAILED = "biometric_failed"
    
    // OAuth errors
    const val OAUTH_ERROR = "oauth_error"
    const val OAUTH_CANCELLED = "oauth_cancelled"
    const val PROVIDER_ERROR = "provider_error"
    
    // Server errors
    const val INTERNAL_ERROR = "internal_error"
    const val SERVICE_UNAVAILABLE = "service_unavailable"
    const val NETWORK_ERROR = "network_error"
    const val TIMEOUT = "timeout"
    
    // SDK errors
    const val NOT_INITIALIZED = "not_initialized"
    const val CONFIGURATION_ERROR = "configuration_error"
    const val STORAGE_ERROR = "storage_error"
    const val CRYPTO_ERROR = "crypto_error"
}

/**
 * Extension function to handle common error patterns
 */
inline fun <T> Result<T>.onVaultError(
    onAuthError: (AuthException) -> Unit = {},
    onNetworkError: (NetworkException) -> Unit = {},
    onValidationError: (ValidationException) -> Unit = {},
    onRateLimit: (RateLimitException) -> Unit = {},
    onOtherError: (VaultException) -> Unit = {}
): Result<T> {
    return onFailure { error ->
        when (error) {
            is AuthException -> onAuthError(error)
            is NetworkException -> onNetworkError(error)
            is ValidationException -> onValidationError(error)
            is RateLimitException -> onRateLimit(error)
            is VaultException -> onOtherError(error)
        }
    }
}

/**
 * Helper to convert Throwable to user-friendly message
 */
fun VaultException.toUserMessage(): String {
    return when (code) {
        ErrorCodes.INVALID_CREDENTIALS -> "Invalid email or password"
        ErrorCodes.EMAIL_NOT_VERIFIED -> "Please verify your email address"
        ErrorCodes.ACCOUNT_DISABLED -> "Your account has been disabled"
        ErrorCodes.RATE_LIMIT_EXCEEDED -> "Too many attempts. Please try again later."
        ErrorCodes.NETWORK_ERROR -> "No internet connection"
        ErrorCodes.TIMEOUT -> "Request timed out"
        ErrorCodes.NOT_FOUND -> "The requested resource was not found"
        ErrorCodes.VALIDATION_ERROR -> "Please check your input and try again"
        ErrorCodes.BIOMETRIC_NOT_ENROLLED -> "Please set up biometric authentication in your device settings"
        ErrorCodes.BIOMETRIC_CANCELLED -> "Authentication was cancelled"
        ErrorCodes.BIOMETRIC_FAILED -> "Biometric authentication failed"
        ErrorCodes.OAUTH_CANCELLED -> "Sign-in was cancelled"
        ErrorCodes.INSUFFICIENT_PERMISSIONS -> "You don't have permission to perform this action"
        else -> message ?: "An unexpected error occurred"
    }
}
