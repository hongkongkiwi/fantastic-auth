package com.vault

import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.vault.models.*
import com.vault.storage.TokenStorage
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.Response
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import retrofit2.http.*
import java.util.Date
import java.util.concurrent.TimeUnit

/**
 * Vault API service interface
 */
internal interface VaultApiService {
    @POST("auth/login")
    suspend fun login(@Body request: LoginRequest): retrofit2.Response<AuthResponse>

    @POST("auth/signup")
    suspend fun signup(@Body request: SignupRequest): retrofit2.Response<AuthResponse>

    @POST("auth/logout")
    suspend fun logout(): retrofit2.Response<Unit>

    @POST("auth/refresh")
    suspend fun refreshToken(@Body request: TokenRefreshRequest): retrofit2.Response<TokenRefreshResponse>

    @POST("auth/verify")
    suspend fun verifyToken(@Body request: TokenVerificationRequest): retrofit2.Response<User>

    @POST("auth/mfa/verify")
    suspend fun verifyMfa(@Body request: MfaVerifyRequest): retrofit2.Response<AuthResponse>

    @POST("auth/mfa/setup")
    suspend fun setupMfa(@Body request: TotpSetupRequest): retrofit2.Response<MfaSetup>

    @POST("auth/mfa/enable")
    suspend fun enableMfa(@Body request: EnableMfaRequest): retrofit2.Response<Unit>

    @POST("auth/mfa/disable")
    suspend fun disableMfa(@Body request: EnableMfaRequest): retrofit2.Response<Unit>

    @GET("organizations")
    suspend fun getOrganizations(): retrofit2.Response<OrganizationListResponse>

    @POST("organizations/switch")
    suspend fun switchOrganization(@Body request: SwitchOrganizationRequest): retrofit2.Response<OrganizationSwitchResponse>

    @GET("user")
    suspend fun getCurrentUser(): retrofit2.Response<User>

    @PATCH("user")
    suspend fun updateUser(@Body request: UserUpdateRequest): retrofit2.Response<User>

    @POST("user/change-password")
    suspend fun changePassword(@Body request: PasswordChangeRequest): retrofit2.Response<Unit>

    @GET("sessions")
    suspend fun getSessions(): retrofit2.Response<List<SessionInfo>>

    @DELETE("sessions/{id}")
    suspend fun revokeSession(@Path("id") sessionId: String): retrofit2.Response<Unit>

    @POST("push/register")
    suspend fun registerPushToken(@Body request: PushTokenRequest): retrofit2.Response<Unit>

    @POST("mfa/push/approve")
    suspend fun approveMfaPush(@Body request: MfaPushRequest): retrofit2.Response<Unit>

    @POST("mfa/push/deny")
    suspend fun denyMfaPush(@Body request: MfaPushRequest): retrofit2.Response<Unit>
}

/**
 * Push token registration request
 */
internal data class PushTokenRequest(
    val token: String,
    val platform: String = "android"
)

/**
 * MFA push request
 */
internal data class MfaPushRequest(
    @SerializedName("request_id")
    val requestId: String
)

/**
 * HTTP interceptor that adds authentication headers
 */
internal class AuthInterceptor(
    private val getAccessToken: () -> String?,
    private val getTenantId: () -> String?
) : Interceptor {
    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request().newBuilder().apply {
            getAccessToken()?.let { token ->
                addHeader("Authorization", "Bearer $token")
            }
            getTenantId()?.let { tenantId ->
                addHeader("X-Tenant-ID", tenantId)
            }
            addHeader("Content-Type", "application/json")
            addHeader("Accept", "application/json")
        }.build()
        return chain.proceed(request)
    }
}

/**
 * HTTP client for Vault API
 */
class VaultClient internal constructor(
    private val storage: TokenStorage,
    private var config: VaultConfig
) {
    private val gson: Gson = GsonBuilder()
        .setDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
        .create()

    private val authInterceptor = AuthInterceptor(
        getAccessToken = { storage.getToken(TokenStorage.KEY_ACCESS_TOKEN) },
        getTenantId = { config.tenantId }
    )

    private val httpClient: OkHttpClient by lazy {
        OkHttpClient.Builder().apply {
            connectTimeout(30, TimeUnit.SECONDS)
            readTimeout(30, TimeUnit.SECONDS)
            writeTimeout(30, TimeUnit.SECONDS)
            addInterceptor(authInterceptor)
            if (config.debug) {
                addInterceptor(HttpLoggingInterceptor().apply {
                    level = HttpLoggingInterceptor.Level.BODY
                })
            }
        }.build()
    }

    private val retrofit: Retrofit by lazy {
        Retrofit.Builder()
            .baseUrl(config.baseUrl)
            .client(httpClient)
            .addConverterFactory(GsonConverterFactory.create(gson))
            .build()
    }

    internal val api: VaultApiService by lazy {
        retrofit.create(VaultApiService::class.java)
    }

    // State flows for reactive updates
    private val _authState = MutableStateFlow<AuthState>(AuthState.Unauthenticated)
    val authState: StateFlow<AuthState> = _authState.asStateFlow()

    private val _currentUser = MutableStateFlow<User?>(null)
    val currentUser: StateFlow<User?> = _currentUser.asStateFlow()

    private val _currentSession = MutableStateFlow<Session?>(null)
    val currentSession: StateFlow<Session?> = _currentSession.asStateFlow()

    private val _currentOrganization = MutableStateFlow<Organization?>(null)
    val currentOrganization: StateFlow<Organization?> = _currentOrganization.asStateFlow()

    /**
     * Update configuration
     */
    fun updateConfig(newConfig: VaultConfig) {
        config = newConfig
    }

    /**
     * Get the current configuration
     */
    fun getConfig(): VaultConfig = config

    /**
     * Set authentication state
     */
    internal fun setAuthenticated(user: User, session: Session) {
        _currentUser.value = user
        _currentSession.value = session
        _authState.value = AuthState.Authenticated(user, session)
        
        // Store tokens
        storage.saveToken(TokenStorage.KEY_ACCESS_TOKEN, session.accessToken)
        storage.saveToken(TokenStorage.KEY_REFRESH_TOKEN, session.refreshToken)
        storage.saveToken(TokenStorage.KEY_USER_DATA, gson.toJson(user))
        storage.saveToken(TokenStorage.KEY_SESSION_DATA, gson.toJson(session))
    }

    /**
     * Clear authentication state
     */
    internal fun clearAuthentication() {
        _currentUser.value = null
        _currentSession.value = null
        _currentOrganization.value = null
        _authState.value = AuthState.Unauthenticated
        storage.clearAll()
    }

    /**
     * Set current organization
     */
    internal fun setCurrentOrganization(organization: Organization?) {
        _currentOrganization.value = organization
    }

    /**
     * Update session with new tokens
     */
    internal fun updateSession(session: Session) {
        _currentSession.value = session
        storage.saveToken(TokenStorage.KEY_ACCESS_TOKEN, session.accessToken)
        storage.saveToken(TokenStorage.KEY_REFRESH_TOKEN, session.refreshToken)
        storage.saveToken(TokenStorage.KEY_SESSION_DATA, gson.toJson(session))
    }

    /**
     * Restore session from storage
     */
    internal fun restoreSession(): Boolean {
        val accessToken = storage.getToken(TokenStorage.KEY_ACCESS_TOKEN) ?: return false
        val refreshToken = storage.getToken(TokenStorage.KEY_REFRESH_TOKEN) ?: return false
        val userJson = storage.getToken(TokenStorage.KEY_USER_DATA) ?: return false
        val sessionJson = storage.getToken(TokenStorage.KEY_SESSION_DATA) ?: return false

        return try {
            val user = gson.fromJson(userJson, User::class.java)
            val session = gson.fromJson(sessionJson, Session::class.java)
            
            // Check if session is expired
            if (session.isExpired()) {
                clearAuthentication()
                return false
            }

            _currentUser.value = user
            _currentSession.value = session
            _authState.value = AuthState.Authenticated(user, session)
            true
        } catch (e: Exception) {
            clearAuthentication()
            false
        }
    }

    /**
     * Check if user is authenticated
     */
    fun isAuthenticated(): Boolean {
        return _authState.value is AuthState.Authenticated
    }
}

/**
 * Vault configuration
 */
data class VaultConfig(
    val apiKey: String,
    val baseUrl: String,
    val tenantId: String? = null,
    val debug: Boolean = false
)

/**
 * Authentication states
 */
sealed class AuthState {
    object Unauthenticated : AuthState()
    data class Authenticated(val user: User, val session: Session) : AuthState()
    data class MfaRequired(val challenge: MfaChallenge) : AuthState()
    data class Error(val exception: VaultAuthException) : AuthState()
}
