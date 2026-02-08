package dev.vault.sdk.auth

import dev.vault.sdk.Vault
import dev.vault.sdk.network.APIClient
import dev.vault.sdk.network.VaultException
import dev.vault.sdk.session.TokenStore
import dev.vault.sdk.session.VaultSession
import dev.vault.sdk.user.User
import dev.vault.sdk.utils.VaultLogger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Authentication service for Vault.
 * Handles email/password, magic link, and token-based authentication.
 */
class VaultAuth {
    
    private val apiClient = APIClient.instance
    private val tokenStore = TokenStore(Vault.context)
    
    /**
     * Sign in with email and password
     * 
     * @param email User's email address
     * @param password User's password
     * @param enableBiometric Whether to enable biometric for future sign-ins
     * @return Session with user and tokens
     * @throws VaultException if authentication fails
     */
    suspend fun signIn(
        email: String,
        password: String,
        enableBiometric: Boolean = false
    ): VaultSession.SessionData = withContext(Dispatchers.IO) {
        VaultLogger.d("Signing in user: $email")
        
        val request = SignInRequest(
            email = email,
            password = password,
            deviceInfo = DeviceInfo.collect()
        )
        
        val response = apiClient.post<SignInRequest, AuthResponse>(
            endpoint = "/auth/signin",
            body = request
        )
        
        response.toSessionData().also { session ->
            tokenStore.saveTokens(
                accessToken = session.accessToken,
                refreshToken = session.refreshToken
            )
            
            if (enableBiometric) {
                tokenStore.enableBiometricKey()
            }
            
            VaultLogger.i("User signed in: ${session.user.id}")
        }
    }
    
    /**
     * Sign up with email and password
     * 
     * @param email User's email address
     * @param password User's password
     * @param name User's full name
     * @return Session with user and tokens
     * @throws VaultException if signup fails
     */
    suspend fun signUp(
        email: String,
        password: String,
        name: String? = null
    ): VaultSession.SessionData = withContext(Dispatchers.IO) {
        VaultLogger.d("Signing up user: $email")
        
        val request = SignUpRequest(
            email = email,
            password = password,
            name = name,
            deviceInfo = DeviceInfo.collect()
        )
        
        val response = apiClient.post<SignUpRequest, AuthResponse>(
            endpoint = "/auth/signup",
            body = request
        )
        
        response.toSessionData().also { session ->
            tokenStore.saveTokens(
                accessToken = session.accessToken,
                refreshToken = session.refreshToken
            )
            VaultLogger.i("User signed up: ${session.user.id}")
        }
    }
    
    /**
     * Sign in with biometric (previously enrolled)
     * 
     * @return Session with user and tokens
     * @throws VaultException if biometric auth fails or not enrolled
     */
    suspend fun signInWithBiometric(): VaultSession.SessionData = withContext(Dispatchers.IO) {
        if (!tokenStore.isBiometricEnabled()) {
            throw VaultException(
                code = "biometric_not_enrolled",
                message = "Biometric authentication not enabled for this account"
            )
        }
        
        val biometricKey = tokenStore.getBiometricKey()
            ?: throw VaultException(
                code = "biometric_key_missing",
                message = "Biometric key not found"
            )
        
        VaultLogger.d("Signing in with biometric")
        
        val request = BiometricAuthRequest(
            keyId = biometricKey.keyId,
            signature = biometricKey.createSignature(),
            deviceInfo = DeviceInfo.collect()
        )
        
        val response = apiClient.post<BiometricAuthRequest, AuthResponse>(
            endpoint = "/auth/biometric",
            body = request
        )
        
        response.toSessionData().also { session ->
            tokenStore.saveTokens(
                accessToken = session.accessToken,
                refreshToken = session.refreshToken
            )
            VaultLogger.i("User signed in with biometric: ${session.user.id}")
        }
    }
    
    /**
     * Request magic link for passwordless sign-in
     * 
     * @param email User's email address
     * @param redirectUrl Optional redirect URL after magic link confirmation
     * @throws VaultException if request fails
     */
    suspend fun requestMagicLink(
        email: String,
        redirectUrl: String? = null
    ) = withContext(Dispatchers.IO) {
        VaultLogger.d("Requesting magic link for: $email")
        
        val request = MagicLinkRequest(
            email = email,
            redirectUrl = redirectUrl
        )
        
        apiClient.post<MagicLinkRequest, Unit>(
            endpoint = "/auth/magic-link",
            body = request
        )
        
        VaultLogger.i("Magic link requested for: $email")
    }
    
    /**
     * Sign in with magic link token
     * 
     * @param token Magic link token from email
     * @return Session with user and tokens
     * @throws VaultException if token is invalid
     */
    suspend fun signInWithMagicLink(token: String): VaultSession.SessionData = 
        withContext(Dispatchers.IO) {
            VaultLogger.d("Signing in with magic link")
            
            val request = MagicLinkSignInRequest(
                token = token,
                deviceInfo = DeviceInfo.collect()
            )
            
            val response = apiClient.post<MagicLinkSignInRequest, AuthResponse>(
                endpoint = "/auth/magic-link/verify",
                body = request
            )
            
            response.toSessionData().also { session ->
                tokenStore.saveTokens(
                    accessToken = session.accessToken,
                    refreshToken = session.refreshToken
                )
                VaultLogger.i("User signed in with magic link: ${session.user.id}")
            }
        }
    
    /**
     * Send password reset email
     * 
     * @param email User's email address
     * @throws VaultException if request fails
     */
    suspend fun forgotPassword(email: String) = withContext(Dispatchers.IO) {
        VaultLogger.d("Requesting password reset for: $email")
        
        val request = ForgotPasswordRequest(email = email)
        
        apiClient.post<ForgotPasswordRequest, Unit>(
            endpoint = "/auth/forgot-password",
            body = request
        )
        
        VaultLogger.i("Password reset requested for: $email")
    }
    
    /**
     * Reset password with token
     * 
     * @param token Reset token from email
     * @param newPassword New password
     * @throws VaultException if token is invalid
     */
    suspend fun resetPassword(
        token: String,
        newPassword: String
    ) = withContext(Dispatchers.IO) {
        VaultLogger.d("Resetting password")
        
        val request = ResetPasswordRequest(
            token = token,
            newPassword = newPassword
        )
        
        apiClient.post<ResetPasswordRequest, Unit>(
            endpoint = "/auth/reset-password",
            body = request
        )
        
        VaultLogger.i("Password reset successful")
    }
    
    /**
     * Verify email address
     * 
     * @param token Verification token from email
     * @throws VaultException if token is invalid
     */
    suspend fun verifyEmail(token: String) = withContext(Dispatchers.IO) {
        VaultLogger.d("Verifying email")
        
        val request = VerifyEmailRequest(token = token)
        
        apiClient.post<VerifyEmailRequest, Unit>(
            endpoint = "/auth/verify-email",
            body = request
        )
        
        VaultLogger.i("Email verified")
    }
    
    /**
     * Resend verification email
     * 
     * @param email User's email address
     * @throws VaultException if request fails
     */
    suspend fun resendVerification(email: String) = withContext(Dispatchers.IO) {
        VaultLogger.d("Resending verification email for: $email")
        
        val request = ResendVerificationRequest(email = email)
        
        apiClient.post<ResendVerificationRequest, Unit>(
            endpoint = "/auth/resend-verification",
            body = request
        )
        
        VaultLogger.i("Verification email resent for: $email")
    }
    
    /**
     * Sign out the current user
     * Clears local tokens and optionally notifies the server
     * 
     * @param revokeAll Whether to revoke all sessions (default: false)
     */
    suspend fun signOut(revokeAll: Boolean = false) = withContext(Dispatchers.IO) {
        VaultLogger.d("Signing out user")
        
        try {
            if (revokeAll) {
                apiClient.post<Unit, Unit>(endpoint = "/auth/signout/all", body = Unit)
            } else {
                apiClient.post<Unit, Unit>(endpoint = "/auth/signout", body = Unit)
            }
        } catch (e: Exception) {
            VaultLogger.w("Failed to notify server of signout: ${e.message}")
        } finally {
            tokenStore.clearTokens()
            VaultLogger.i("User signed out")
        }
    }
    
    // Data classes for requests and responses
    
    private data class SignInRequest(
        val email: String,
        val password: String,
        val deviceInfo: DeviceInfo
    )
    
    private data class SignUpRequest(
        val email: String,
        val password: String,
        val name: String?,
        val deviceInfo: DeviceInfo
    )
    
    private data class BiometricAuthRequest(
        val keyId: String,
        val signature: String,
        val deviceInfo: DeviceInfo
    )
    
    private data class MagicLinkRequest(
        val email: String,
        val redirectUrl: String?
    )
    
    private data class MagicLinkSignInRequest(
        val token: String,
        val deviceInfo: DeviceInfo
    )
    
    private data class ForgotPasswordRequest(val email: String)
    
    private data class ResetPasswordRequest(
        val token: String,
        val newPassword: String
    )
    
    private data class VerifyEmailRequest(val token: String)
    
    private data class ResendVerificationRequest(val email: String)
    
    private data class AuthResponse(
        val user: User,
        val accessToken: String,
        val refreshToken: String,
        val expiresIn: Long,
        val tokenType: String = "Bearer"
    ) {
        fun toSessionData() = VaultSession.SessionData(
            user = user,
            accessToken = accessToken,
            refreshToken = refreshToken,
            expiresIn = expiresIn,
            tokenType = tokenType
        )
    }
}
