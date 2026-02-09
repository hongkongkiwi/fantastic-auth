package dev.vault.sdk.auth

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.Uri
import dev.vault.sdk.Vault
import dev.vault.sdk.network.APIClient
import dev.vault.sdk.network.VaultException
import dev.vault.sdk.session.TokenStore
import dev.vault.sdk.session.VaultSession
import dev.vault.sdk.user.User
import dev.vault.sdk.utils.VaultLogger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlin.coroutines.Continuation
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * OAuth providers supported by Vault
 */
enum class OAuthProvider(val providerName: String) {
    GOOGLE("google"),
    APPLE("apple"),
    GITHUB("github"),
    MICROSOFT("microsoft"),
    SLACK("slack"),
    DISCORD("discord");
    
    companion object {
        fun fromString(name: String): OAuthProvider? =
            values().find { it.providerName == name.lowercase() }
    }
}

/**
 * OAuth authentication handler
 */
class VaultOAuth {
    
    private val apiClient = APIClient.instance
    private val tokenStore = TokenStore(Vault.context)
    
    /**
     * Initiate OAuth sign-in flow
     * 
     * @param activity The calling activity
     * @param provider OAuth provider (Google, Apple, etc.)
     * @param scopes Optional OAuth scopes
     * @return Session data after successful authentication
     * @throws VaultException if authentication fails
     */
    suspend fun signInWith(
        activity: Activity,
        provider: OAuthProvider,
        scopes: List<String> = emptyList()
    ): VaultSession.SessionData = withContext(Dispatchers.Main) {
        VaultLogger.d("Starting OAuth flow for provider: ${provider.providerName}")
        
        val state = generateState()
        val (authUrl, codeVerifier) = getAuthorizationUrl(provider, state, scopes)
        
        suspendCancellableCoroutine { continuation ->
            OAuthCallbackActivity.registerCallback(state, continuation)
            
            val intent = Intent(Intent.ACTION_VIEW, Uri.parse(authUrl))
            activity.startActivity(intent)
            
            continuation.invokeOnCancellation {
                OAuthCallbackActivity.unregisterCallback(state)
            }
        }.let { result ->
            handleCallbackResult(result as OAuthCallbackResult, provider, codeVerifier)
        }
    }
    
    /**
     * Handle OAuth callback URI (typically called from deep link handler)
     * 
     * @param uri The callback URI
     * @return true if the URI was handled
     */
    fun handleCallback(uri: Uri): Boolean {
        return OAuthCallbackActivity.handleCallback(uri)
    }
    
    /**
     * Link OAuth provider to existing account
     * 
     * @param activity The calling activity
     * @param provider OAuth provider to link
     * @throws VaultException if linking fails
     */
    suspend fun linkProvider(
        activity: Activity,
        provider: OAuthProvider
    ) = withContext(Dispatchers.IO) {
        VaultLogger.d("Linking OAuth provider: ${provider.providerName}")
        
        val state = generateState()
        val (authUrl, _) = getAuthorizationUrl(provider, state, emptyList(), link = true)
        
        val result = suspendCancellableCoroutine<OAuthCallbackResult> { continuation ->
            OAuthCallbackActivity.registerCallback(state, continuation)
            
            val intent = Intent(Intent.ACTION_VIEW, Uri.parse(authUrl))
            activity.startActivity(intent)
            
            continuation.invokeOnCancellation {
                OAuthCallbackActivity.unregisterCallback(state)
            }
        }
        
        if (result is OAuthCallbackResult.Success) {
            apiClient.post<Map<String, String>, Unit>(
                endpoint = "/auth/oauth/link",
                body = mapOf(
                    "provider" to provider.providerName,
                    "code" to result.code
                )
            )
            VaultLogger.i("OAuth provider linked: ${provider.providerName}")
        } else if (result is OAuthCallbackResult.Error) {
            throw VaultException(code = result.error, message = result.errorDescription)
        }
    }
    
    /**
     * Unlink OAuth provider from account
     * 
     * @param provider OAuth provider to unlink
     * @throws VaultException if unlinking fails
     */
    suspend fun unlinkProvider(provider: OAuthProvider) = withContext(Dispatchers.IO) {
        VaultLogger.d("Unlinking OAuth provider: ${provider.providerName}")
        
        apiClient.post<Map<String, String>, Unit>(
            endpoint = "/auth/oauth/unlink",
            body = mapOf("provider" to provider.providerName)
        )
        
        VaultLogger.i("OAuth provider unlinked: ${provider.providerName}")
    }
    
    /**
     * Get list of linked OAuth providers
     * 
     * @return List of linked provider names
     */
    suspend fun getLinkedProviders(): List<String> = withContext(Dispatchers.IO) {
        val response = apiClient.get<LinkedProvidersResponse>(
            endpoint = "/auth/oauth/providers"
        )
        response.providers
    }
    
    private suspend fun getAuthorizationUrl(
        provider: OAuthProvider,
        state: String,
        scopes: List<String>,
        link: Boolean = false
    ): Pair<String, String?> {
        val request = AuthorizationUrlRequest(
            provider = provider.providerName,
            state = state,
            scopes = scopes.takeIf { it.isNotEmpty() },
            redirectUri = "vault://oauth/callback",
            link = link
        )
        
        val response = apiClient.post<AuthorizationUrlRequest, AuthorizationUrlResponse>(
            endpoint = "/auth/oauth/authorize",
            body = request
        )
        
        return response.url to response.codeVerifier
    }
    
    private suspend fun handleCallbackResult(
        result: OAuthCallbackResult,
        provider: OAuthProvider,
        codeVerifier: String?
    ): VaultSession.SessionData {
        return when (result) {
            is OAuthCallbackResult.Success -> {
                VaultLogger.d("OAuth callback success, exchanging code for tokens")
                
                val request = TokenExchangeRequest(
                    provider = provider.providerName,
                    code = result.code,
                    codeVerifier = codeVerifier,
                    deviceInfo = DeviceInfo.collect()
                )
                
                val response = apiClient.post<TokenExchangeRequest, OAuthTokenResponse>(
                    endpoint = "/auth/oauth/token",
                    body = request
                )
                
                response.toSessionData().also { session ->
                    tokenStore.saveTokens(
                        accessToken = session.accessToken,
                        refreshToken = session.refreshToken
                    )
                    VaultLogger.i("OAuth sign-in successful: ${session.user.id}")
                }
            }
            is OAuthCallbackResult.Error -> {
                throw VaultException(
                    code = result.error,
                    message = result.errorDescription ?: "OAuth authentication failed"
                )
            }
            is OAuthCallbackResult.Cancelled -> {
                throw VaultException(
                    code = "oauth_cancelled",
                    message = "OAuth authentication was cancelled"
                )
            }
        }
    }
    
    private fun generateState(): String {
        return java.util.UUID.randomUUID().toString()
    }
    
    // Data classes
    
    private data class AuthorizationUrlRequest(
        val provider: String,
        val state: String,
        val scopes: List<String>?,
        val redirectUri: String,
        val link: Boolean
    )
    
    private data class AuthorizationUrlResponse(
        val url: String,
        val codeVerifier: String?
    )
    
    private data class TokenExchangeRequest(
        val provider: String,
        val code: String,
        val codeVerifier: String?,
        val deviceInfo: DeviceInfo
    )
    
    private data class OAuthTokenResponse(
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
    
    private data class LinkedProvidersResponse(
        val providers: List<String>
    )
}

/**
 * OAuth callback result
 */
sealed class OAuthCallbackResult {
    data class Success(val code: String, val state: String) : OAuthCallbackResult()
    data class Error(val error: String, val errorDescription: String?) : OAuthCallbackResult()
    object Cancelled : OAuthCallbackResult()
}

/**
 * Activity to handle OAuth callbacks
 */
class OAuthCallbackActivity : Activity() {
    
    override fun onCreate(savedInstanceState: android.os.Bundle?) {
        super.onCreate(savedInstanceState)
        
        intent?.data?.let { uri ->
            if (handleCallback(uri)) {
                finish()
                return
            }
        }
        
        finish()
    }
    
    companion object {
        private val callbacks = mutableMapOf<String, Continuation<OAuthCallbackResult>>()
        
        fun registerCallback(state: String, continuation: Continuation<OAuthCallbackResult>) {
            callbacks[state] = continuation
        }
        
        fun unregisterCallback(state: String) {
            callbacks.remove(state)
        }
        
        fun handleCallback(uri: Uri): Boolean {
            if (uri.scheme != "vault" || uri.host != "oauth") {
                return false
            }
            
            val state = uri.getQueryParameter("state")
            val code = uri.getQueryParameter("code")
            val error = uri.getQueryParameter("error")
            val errorDescription = uri.getQueryParameter("error_description")
            
            val continuation = state?.let { callbacks.remove(it) }
            
            continuation?.let {
                when {
                    code != null -> {
                        it.resume(OAuthCallbackResult.Success(code, state))
                    }
                    error != null -> {
                        it.resume(OAuthCallbackResult.Error(error, errorDescription))
                    }
                    else -> {
                        it.resume(OAuthCallbackResult.Cancelled)
                    }
                }
                return true
            }
            
            return false
        }
    }
}

/**
 * Device information for authentication requests
 */
internal data class DeviceInfo(
    val deviceId: String,
    val platform: String = "android",
    val model: String,
    val osVersion: String,
    val appVersion: String
) {
    companion object {
        fun collect(): DeviceInfo {
            val context = Vault.context
            val prefs = context.getSharedPreferences("vault_device", Context.MODE_PRIVATE)
            var deviceId = prefs.getString("device_id", null)
            
            if (deviceId == null) {
                deviceId = java.util.UUID.randomUUID().toString()
                prefs.edit().putString("device_id", deviceId).apply()
            }
            
            val packageInfo = context.packageManager.getPackageInfo(context.packageName, 0)
            
            return DeviceInfo(
                deviceId = deviceId,
                model = android.os.Build.MODEL,
                osVersion = android.os.Build.VERSION.RELEASE,
                appVersion = packageInfo.versionName ?: "unknown"
            )
        }
    }
}
