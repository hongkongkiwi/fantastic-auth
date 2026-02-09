package dev.vault.sdk.session

import dev.vault.sdk.Vault
import dev.vault.sdk.network.APIClient
import dev.vault.sdk.network.VaultException
import dev.vault.sdk.user.User
import dev.vault.sdk.utils.VaultLogger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import java.util.Date

/**
 * Session manager for Vault
 */
class VaultSession {
    
    private val apiClient = APIClient.instance
    private val tokenStore = TokenStore(Vault.context)
    
    companion object {
        private val _currentUser = MutableStateFlow<User?>(null)
        
        /**
         * Current user as StateFlow for reactive UI updates
         */
        val currentUserFlow: StateFlow<User?> = _currentUser.asStateFlow()
        
        /**
         * Update the current user in the flow
         */
        internal fun updateCurrentUser(user: User?) {
            _currentUser.value = user
        }
    }
    
    /**
     * Current session data (if authenticated)
     */
    val currentSession: SessionData?
        get() = tokenStore.getAccessToken()?.let { token ->
            SessionData(
                user = _currentUser.value ?: return@let null,
                accessToken = token,
                refreshToken = tokenStore.getRefreshToken() ?: "",
                expiresIn = tokenStore.getTokenExpiry()?.time?.minus(System.currentTimeMillis())?.div(1000) ?: 0,
                tokenType = "Bearer"
            )
        }
    
    /**
     * Current user (if authenticated)
     */
    val currentUser: User?
        get() = _currentUser.value
    
    /**
     * Whether a user is currently authenticated
     */
    val isAuthenticated: Boolean
        get() = tokenStore.getAccessToken() != null && _currentUser.value != null
    
    /**
     * Get the current access token
     * 
     * @return Access token or null if not authenticated
     */
    fun getToken(): String? = tokenStore.getAccessToken()
    
    /**
     * Get the current refresh token
     * 
     * @return Refresh token or null if not authenticated
     */
    fun getRefreshToken(): String? = tokenStore.getRefreshToken()
    
    /**
     * Restore session from stored tokens
     * Call this on app startup to restore the previous session
     * 
     * @return true if session was restored successfully
     */
    suspend fun restoreSession(): Boolean = withContext(Dispatchers.IO) {
        val accessToken = tokenStore.getAccessToken()
        val refreshToken = tokenStore.getRefreshToken()
        
        if (accessToken == null && refreshToken == null) {
            VaultLogger.d("No stored session to restore")
            return@withContext false
        }
        
        // Try to get current user to validate token
        try {
            val user: User = apiClient.get("/users/me")
            updateCurrentUser(user)
            VaultLogger.i("Session restored for user: ${user.id}")
            true
        } catch (e: VaultException) {
            if (e.code == "token_expired" && refreshToken != null) {
                // Try to refresh token
                tryRefreshToken()
            } else {
                VaultLogger.w("Failed to restore session: ${e.message}")
                clearSession()
                false
            }
        }
    }
    
    /**
     * Refresh the access token using the refresh token
     * 
     * @return true if token was refreshed successfully
     */
    suspend fun refreshToken(): Boolean = withContext(Dispatchers.IO) {
        tryRefreshToken()
    }
    
    /**
     * Sign out the current user
     * 
     * @param revokeAll Whether to revoke all sessions
     */
    suspend fun signOut(revokeAll: Boolean = false) = withContext(Dispatchers.IO) {
        try {
            if (revokeAll) {
                apiClient.post<Unit, Unit>(endpoint = "/auth/signout/all", body = Unit)
            } else {
                apiClient.post<Unit, Unit>(endpoint = "/auth/signout", body = Unit)
            }
        } catch (e: Exception) {
            VaultLogger.w("Server signout failed: ${e.message}")
        } finally {
            clearSession()
        }
    }
    
    /**
     * Update the current user data from server
     * 
     * @return Updated user
     */
    suspend fun refreshUser(): User = withContext(Dispatchers.IO) {
        val user: User = apiClient.get("/users/me")
        updateCurrentUser(user)
        user
    }
    
    /**
     * Set session data directly (useful for testing or custom auth flows)
     * 
     * @param sessionData Session data to set
     */
    fun setSession(sessionData: SessionData) {
        tokenStore.saveTokens(
            accessToken = sessionData.accessToken,
            refreshToken = sessionData.refreshToken,
            expiresIn = sessionData.expiresIn
        )
        updateCurrentUser(sessionData.user)
    }
    
    private suspend fun tryRefreshToken(): Boolean {
        val refreshToken = tokenStore.getRefreshToken()
            ?: return false.also { clearSession() }
        
        return try {
            val request = RefreshTokenRequest(refreshToken = refreshToken)
            val response: TokenResponse = apiClient.post(
                endpoint = "/auth/refresh",
                body = request
            )
            
            tokenStore.saveTokens(
                accessToken = response.accessToken,
                refreshToken = response.refreshToken,
                expiresIn = response.expiresIn
            )
            
            // Refresh user data
            val user: User = apiClient.get("/users/me")
            updateCurrentUser(user)
            
            VaultLogger.i("Token refreshed successfully")
            true
        } catch (e: Exception) {
            VaultLogger.w("Token refresh failed: ${e.message}")
            clearSession()
            false
        }
    }
    
    private fun clearSession() {
        tokenStore.clearTokens()
        updateCurrentUser(null)
        VaultLogger.i("Session cleared")
    }
    
    // Data classes
    
    data class SessionData(
        val user: User,
        val accessToken: String,
        val refreshToken: String,
        val expiresIn: Long,
        val tokenType: String
    )
    
    private data class RefreshTokenRequest(
        val refreshToken: String
    )
    
    private data class TokenResponse(
        val accessToken: String,
        val refreshToken: String,
        val expiresIn: Long,
        val tokenType: String
    )
}

/**
 * Extension for suspending operations with automatic token refresh
 */
suspend fun <T> withTokenRefresh(block: suspend () -> T): T {
    return try {
        block()
    } catch (e: VaultException) {
        if (e.code == "token_expired") {
            val session = VaultSession()
            if (session.refreshToken()) {
                block()
            } else {
                throw e
            }
        } else {
            throw e
        }
    }
}
