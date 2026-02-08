package com.vault

import android.app.Activity
import android.content.Context
import android.content.Intent
import androidx.fragment.app.FragmentActivity
import com.vault.biometric.BiometricAuth
import com.vault.biometric.BiometricType
import com.vault.models.*
import com.vault.storage.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.withContext
import com.google.gson.Gson
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Main Vault Authentication SDK class
 * 
 * Usage:
 * ```kotlin
 * // Initialize in Application.onCreate()
 * VaultAuth.getInstance().configure(
 *     context = applicationContext,
 *     apiKey = "your_api_key",
 *     baseUrl = "https://vault.example.com",
 *     tenantId = "your_tenant_id"
 * )
 * 
 * // Login
 * val user = VaultAuth.getInstance().login("user@example.com", "password")
 * ```
 */
class VaultAuth private constructor() {

    private var vaultClient: VaultClient? = null
    private var tokenStorage: TokenStorage? = null
    private var config: VaultConfig? = null
    private val gson = Gson()
    private val mutex = Mutex()

    companion object {
        @Volatile
        private var instance: VaultAuth? = null

        /**
         * Get the singleton instance of VaultAuth
         */
        @JvmStatic
        fun getInstance(): VaultAuth {
            return instance ?: synchronized(this) {
                instance ?: VaultAuth().also { instance = it }
            }
        }

        /**
         * Clear the singleton instance (useful for testing)
         */
        @JvmStatic
        fun clearInstance() {
            instance = null
        }
    }

    /**
     * Configure the VaultAuth SDK
     * 
     * @param context Application context
     * @param apiKey Your Vault API key
     * @param baseUrl The base URL of your Vault server
     * @param tenantId Optional tenant ID for multi-tenant setups
     * @param debug Enable debug logging
     * @param storage Custom token storage implementation (optional)
     */
    @JvmOverloads
    fun configure(
        context: Context,
        apiKey: String,
        baseUrl: String,
        tenantId: String? = null,
        debug: Boolean = false,
        storage: TokenStorage? = null
    ) {
        if (vaultClient != null) {
            throw VaultAuthException.InvalidConfiguration("VaultAuth is already configured")
        }

        val normalizedBaseUrl = if (baseUrl.endsWith("/")) baseUrl else "$baseUrl/"
        
        config = VaultConfig(
            apiKey = apiKey,
            baseUrl = normalizedBaseUrl,
            tenantId = tenantId,
            debug = debug
        )

        tokenStorage = storage ?: KeystoreStorage(context.applicationContext)
        vaultClient = VaultClient(tokenStorage!!, config!!)
        
        // Try to restore previous session
        vaultClient?.restoreSession()
    }

    /**
     * Check if the SDK has been configured
     */
    fun isConfigured(): Boolean = vaultClient != null

    private fun getClient(): VaultClient {
        return vaultClient ?: throw VaultAuthException.NotConfigured()
    }

    private fun getStorage(): TokenStorage {
        return tokenStorage ?: throw VaultAuthException.NotConfigured()
    }

    // ============================================================================
    // Authentication State
    // ============================================================================

    /**
     * Current authentication state flow
     */
    val authState: StateFlow<AuthState>?
        get() = vaultClient?.authState

    /**
     * Current authenticated user
     */
    val currentUser: User?
        get() = vaultClient?.currentUser?.value

    /**
     * Current session
     */
    val currentSession: Session?
        get() = vaultClient?.currentSession?.value

    /**
     * Current organization
     */
    val currentOrganization: Organization?
        get() = vaultClient?.currentOrganization?.value

    /**
     * Check if user is currently authenticated
     */
    val isAuthenticated: Boolean
        get() = vaultClient?.isAuthenticated() == true

    // ============================================================================
    // Authentication Methods
    // ============================================================================

    /**
     * Login with email and password
     * 
     * @param email User's email
     * @param password User's password
     * @return The authenticated User
     * @throws VaultAuthException if authentication fails
     */
    suspend fun login(email: String, password: String): User = withContext(Dispatchers.IO) {
        val client = getClient()
        val tenantId = config?.tenantId

        val response = client.api.login(LoginRequest(email, password, tenantId))

        if (response.isSuccessful) {
            val authResponse = response.body()
                ?: throw VaultAuthException.DecodingError(Exception("Empty response body"))
            
            client.setAuthenticated(authResponse.user, authResponse.session)
            authResponse.user
        } else {
            val errorBody = response.errorBody()?.string()
            val apiError = errorBody?.let { 
                try {
                    gson.fromJson(it, ApiErrorResponse::class.java)
                } catch (e: Exception) {
                    ApiErrorResponse("unknown", errorBody)
                }
            } ?: ApiErrorResponse("unknown", "Unknown error")
            
            throw apiError.toException(response.code())
        }
    }

    /**
     * Login with biometric authentication
     * Requires that biometric login has been previously enabled
     * 
     * @param activity The activity for showing biometric prompt
     * @return The authenticated User
     * @throws VaultAuthException if authentication fails
     */
    suspend fun loginWithBiometric(activity: FragmentActivity): User = withContext(Dispatchers.Main) {
        val biometricAuth = BiometricAuth(activity)
        
        if (!biometricAuth.isAvailable) {
            throw VaultAuthException.BiometricNotAvailable()
        }

        val storage = getStorage()
        
        // First authenticate with biometric
        biometricAuth.authenticate(
            title = "Log In",
            subtitle = "Use your biometric to log in",
            negativeButtonText = "Use Password"
        )

        // Get the biometric-protected token
        val biometricToken = storage.getToken(TokenStorage.KEY_BIOMETRIC_TOKEN)
            ?: throw VaultAuthException.TokenNotFound()

        // Verify the token with the server
        verifyToken(biometricToken)
    }

    /**
     * Sign up a new user
     * 
     * @param email User's email
     * @param password User's password
     * @param name User's full name (optional)
     * @return The created User
     * @throws VaultAuthException if signup fails
     */
    suspend fun signup(email: String, password: String, name: String? = null): User = withContext(Dispatchers.IO) {
        val client = getClient()
        val tenantId = config?.tenantId

        val response = client.api.signup(SignupRequest(email, password, name, tenantId))

        if (response.isSuccessful) {
            val authResponse = response.body()
                ?: throw VaultAuthException.DecodingError(Exception("Empty response body"))
            
            client.setAuthenticated(authResponse.user, authResponse.session)
            authResponse.user
        } else {
            val errorBody = response.errorBody()?.string()
            val apiError = errorBody?.let { 
                try {
                    gson.fromJson(it, ApiErrorResponse::class.java)
                } catch (e: Exception) {
                    ApiErrorResponse("unknown", errorBody)
                }
            } ?: ApiErrorResponse("unknown", "Unknown error")
            
            throw apiError.toException(response.code())
        }
    }

    /**
     * Logout the current user
     */
    suspend fun logout() = withContext(Dispatchers.IO) {
        val client = getClient()
        
        try {
            client.api.logout()
        } catch (e: Exception) {
            // Continue with local logout even if server logout fails
        } finally {
            client.clearAuthentication()
        }
    }

    /**
     * Verify a token with the server
     * 
     * @param token The token to verify
     * @return The user associated with the token
     */
    suspend fun verifyToken(token: String): User = withContext(Dispatchers.IO) {
        val client = getClient()

        val response = client.api.verifyToken(TokenVerificationRequest(token))

        if (response.isSuccessful) {
            response.body() ?: throw VaultAuthException.DecodingError(Exception("Empty response body"))
        } else {
            val errorBody = response.errorBody()?.string()
            val apiError = errorBody?.let { 
                try {
                    gson.fromJson(it, ApiErrorResponse::class.java)
                } catch (e: Exception) {
                    ApiErrorResponse("unknown", errorBody)
                }
            } ?: ApiErrorResponse("unknown", "Unknown error")
            
            throw apiError.toException(response.code())
        }
    }

    /**
     * Refresh the current session
     */
    suspend fun refreshSession() = withContext(Dispatchers.IO) {
        val client = getClient()
        val storage = getStorage()
        
        val refreshToken = storage.getToken(TokenStorage.KEY_REFRESH_TOKEN)
            ?: throw VaultAuthException.TokenNotFound()

        val response = client.api.refreshToken(TokenRefreshRequest(refreshToken))

        if (response.isSuccessful) {
            val refreshResponse = response.body()
                ?: throw VaultAuthException.DecodingError(Exception("Empty response body"))
            
            val currentUser = client.currentUser.value
                ?: throw VaultAuthException.SessionExpired()
            
            val newSession = Session(
                id = currentSession?.id ?: "",
                accessToken = refreshResponse.accessToken,
                refreshToken = refreshResponse.refreshToken ?: refreshToken,
                expiresAt = refreshResponse.expiresAt,
                user = currentUser
            )
            
            client.updateSession(newSession)
        } else {
            client.clearAuthentication()
            throw VaultAuthException.TokenRefreshFailed()
        }
    }

    // ============================================================================
    // OAuth
    // ============================================================================

    /**
     * Login with OAuth provider
     * 
     * @param provider The OAuth provider (GOOGLE, GITHUB, MICROSOFT, etc.)
     * @param activity The activity for OAuth flow
     * @return The authenticated User
     */
    suspend fun loginWithOAuth(provider: OAuthProvider, activity: Activity): User {
        // This would typically launch a custom tab or WebView for OAuth
        // Implementation depends on the specific OAuth flow
        throw VaultAuthException.OAuthFailed("OAuth not implemented. Use OAuth libraries like AppAuth.")
    }

    /**
     * Handle OAuth callback
     * Call this from your OAuth callback activity
     * 
     * @param intent The intent containing the OAuth callback
     * @return The authenticated User
     */
    suspend fun handleOAuthCallback(intent: Intent): User {
        // Parse the OAuth callback and exchange code for tokens
        throw VaultAuthException.OAuthFailed("OAuth not implemented. Use OAuth libraries like AppAuth.")
    }

    // ============================================================================
    // MFA
    // ============================================================================

    /**
     * Enable MFA for the current user
     * 
     * @param method The MFA method to enable
     * @return MFA setup information (including QR code for TOTP)
     */
    suspend fun enableMfa(method: MfaMethod): MfaSetup = withContext(Dispatchers.IO) {
        val client = getClient()

        if (method == MfaMethod.TOTP) {
            val response = client.api.setupMfa(TotpSetupRequest())
            
            if (response.isSuccessful) {
                response.body() ?: throw VaultAuthException.DecodingError(Exception("Empty response body"))
            } else {
                val errorBody = response.errorBody()?.string()
                val apiError = errorBody?.let { 
                    try {
                        gson.fromJson(it, ApiErrorResponse::class.java)
                    } catch (e: Exception) {
                        ApiErrorResponse("unknown", errorBody)
                    }
                } ?: ApiErrorResponse("unknown", "Unknown error")
                
                throw apiError.toException(response.code())
            }
        } else {
            val response = client.api.enableMfa(EnableMfaRequest(method))
            
            if (!response.isSuccessful) {
                val errorBody = response.errorBody()?.string()
                throw VaultAuthException.MfaSetupFailed(errorBody ?: "Failed to enable MFA")
            }
            
            MfaSetup("", "", emptyList())
        }
    }

    /**
     * Verify MFA code during login
     * 
     * @param code The MFA code
     * @param method The MFA method
     */
    suspend fun verifyMfa(code: String, method: MfaMethod = MfaMethod.TOTP): Unit = withContext(Dispatchers.IO) {
        val client = getClient()

        val response = client.api.verifyMfa(MfaVerifyRequest(code, method))

        if (response.isSuccessful) {
            val authResponse = response.body()
                ?: throw VaultAuthException.DecodingError(Exception("Empty response body"))
            
            client.setAuthenticated(authResponse.user, authResponse.session)
        } else {
            val errorBody = response.errorBody()?.string()
            val apiError = errorBody?.let { 
                try {
                    gson.fromJson(it, ApiErrorResponse::class.java)
                } catch (e: Exception) {
                    ApiErrorResponse("unknown", errorBody)
                }
            } ?: ApiErrorResponse("unknown", "Unknown error")
            
            throw apiError.toException(response.code())
        }
    }

    /**
     * Disable MFA for the current user
     * 
     * @param method The MFA method to disable
     */
    suspend fun disableMfa(method: MfaMethod) = withContext(Dispatchers.IO) {
        val client = getClient()

        val response = client.api.disableMfa(EnableMfaRequest(method))

        if (!response.isSuccessful) {
            val errorBody = response.errorBody()?.string()
            throw VaultAuthException.MfaSetupFailed(errorBody ?: "Failed to disable MFA")
        }
    }

    // ============================================================================
    // Organizations
    // ============================================================================

    /**
     * Get all organizations for the current user
     * 
     * @return List of organizations
     */
    suspend fun getOrganizations(): List<Organization> = withContext(Dispatchers.IO) {
        val client = getClient()

        val response = client.api.getOrganizations()

        if (response.isSuccessful) {
            val orgResponse = response.body()
            orgResponse?.organizations ?: emptyList()
        } else {
            val errorBody = response.errorBody()?.string()
            val apiError = errorBody?.let { 
                try {
                    gson.fromJson(it, ApiErrorResponse::class.java)
                } catch (e: Exception) {
                    ApiErrorResponse("unknown", errorBody)
                }
            } ?: ApiErrorResponse("unknown", "Unknown error")
            
            throw apiError.toException(response.code())
        }
    }

    /**
     * Switch to a different organization
     * 
     * @param organizationId The ID of the organization to switch to
     */
    suspend fun switchOrganization(organizationId: String) = withContext(Dispatchers.IO) {
        val client = getClient()

        val response = client.api.switchOrganization(SwitchOrganizationRequest(organizationId))

        if (response.isSuccessful) {
            val switchResponse = response.body()
                ?: throw VaultAuthException.DecodingError(Exception("Empty response body"))
            
            client.setCurrentOrganization(switchResponse.organization)
            client.updateSession(switchResponse.session)
        } else {
            throw VaultAuthException.OrganizationSwitchFailed()
        }
    }

    // ============================================================================
    // User Management
    // ============================================================================

    /**
     * Update the current user
     * 
     * @param request The update request
     * @return The updated User
     */
    suspend fun updateUser(request: UserUpdateRequest): User = withContext(Dispatchers.IO) {
        val client = getClient()

        val response = client.api.updateUser(request)

        if (response.isSuccessful) {
            response.body() ?: throw VaultAuthException.DecodingError(Exception("Empty response body"))
        } else {
            val errorBody = response.errorBody()?.string()
            val apiError = errorBody?.let { 
                try {
                    gson.fromJson(it, ApiErrorResponse::class.java)
                } catch (e: Exception) {
                    ApiErrorResponse("unknown", errorBody)
                }
            } ?: ApiErrorResponse("unknown", "Unknown error")
            
            throw apiError.toException(response.code())
        }
    }

    /**
     * Change the current user's password
     * 
     * @param currentPassword The current password
     * @param newPassword The new password
     */
    suspend fun changePassword(currentPassword: String, newPassword: String) = withContext(Dispatchers.IO) {
        val client = getClient()

        val response = client.api.changePassword(PasswordChangeRequest(currentPassword, newPassword))

        if (!response.isSuccessful) {
            val errorBody = response.errorBody()?.string()
            val apiError = errorBody?.let { 
                try {
                    gson.fromJson(it, ApiErrorResponse::class.java)
                } catch (e: Exception) {
                    ApiErrorResponse("unknown", errorBody)
                }
            } ?: ApiErrorResponse("unknown", "Unknown error")
            
            throw apiError.toException(response.code())
        }
    }

    // ============================================================================
    // Session Management
    // ============================================================================

    /**
     * Get all active sessions for the current user
     * 
     * @return List of session information
     */
    suspend fun getSessions(): List<SessionInfo> = withContext(Dispatchers.IO) {
        val client = getClient()

        val response = client.api.getSessions()

        if (response.isSuccessful) {
            response.body() ?: emptyList()
        } else {
            emptyList()
        }
    }

    /**
     * Revoke a specific session
     * 
     * @param sessionId The ID of the session to revoke
     */
    suspend fun revokeSession(sessionId: String) = withContext(Dispatchers.IO) {
        val client = getClient()
        client.api.revokeSession(sessionId)
    }

    /**
     * Revoke all other sessions except the current one
     */
    suspend fun revokeAllOtherSessions() = withContext(Dispatchers.IO) {
        val client = getClient()
        val sessions = getSessions()
        
        val currentSessionId = currentSession?.id
        
        sessions.forEach { session ->
            if (!session.isCurrent && session.id != currentSessionId) {
                try {
                    client.api.revokeSession(session.id)
                } catch (e: Exception) {
                    // Continue revoking other sessions
                }
            }
        }
    }

    // ============================================================================
    // Biometric
    // ============================================================================

    /**
     * Enable biometric login for the current user
     * 
     * @param activity The activity for showing biometric prompt
     */
    suspend fun enableBiometricLogin(activity: FragmentActivity) = withContext(Dispatchers.Main) {
        val biometricAuth = BiometricAuth(activity)
        
        if (!biometricAuth.isAvailable) {
            throw VaultAuthException.BiometricNotAvailable()
        }

        // Authenticate with biometric
        biometricAuth.authenticate(
            title = "Enable Biometric Login",
            subtitle = "Verify your identity to enable biometric login",
            description = "You'll be able to log in using your biometric credentials in the future."
        )

        // Store a special token for biometric login
        val session = currentSession ?: throw VaultAuthException.SessionExpired()
        val storage = getStorage()
        
        // Store the refresh token with biometric protection
        storage.saveToken(TokenStorage.KEY_BIOMETRIC_TOKEN, session.refreshToken)
    }

    /**
     * Disable biometric login
     */
    fun disableBiometricLogin() {
        val storage = getStorage()
        storage.deleteToken(TokenStorage.KEY_BIOMETRIC_TOKEN)
    }

    /**
     * Check if biometric login is enabled
     */
    fun isBiometricLoginEnabled(): Boolean {
        return getStorage().hasToken(TokenStorage.KEY_BIOMETRIC_TOKEN)
    }

    /**
     * Check if biometric authentication is available on this device
     */
    fun isBiometricAvailable(context: Context): Boolean {
        return BiometricAuth.isAvailable(context)
    }

    /**
     * Get the type of biometric available
     */
    fun getBiometricType(context: Context): BiometricType {
        return BiometricAuth.getBiometricType(context)
    }

    // ============================================================================
    // Push Notifications
    // ============================================================================

    /**
     * Register for push notifications
     * 
     * @param token The FCM token
     */
    suspend fun registerForPushNotifications(token: String) = withContext(Dispatchers.IO) {
        val client = getClient()
        
        try {
            client.api.registerPushToken(PushTokenRequest(token))
        } catch (e: Exception) {
            // Log but don't throw - push registration is not critical
        }
    }

    /**
     * Approve an MFA push request
     * 
     * @param requestId The MFA request ID
     */
    suspend fun approveMfaRequest(requestId: String) = withContext(Dispatchers.IO) {
        val client = getClient()
        client.api.approveMfaPush(MfaPushRequest(requestId))
    }

    /**
     * Deny an MFA push request
     * 
     * @param requestId The MFA request ID
     */
    suspend fun denyMfaRequest(requestId: String) = withContext(Dispatchers.IO) {
        val client = getClient()
        client.api.denyMfaPush(MfaPushRequest(requestId))
    }
}
