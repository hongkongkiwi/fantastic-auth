package dev.vault.sdk

import android.content.Context
import dev.vault.sdk.auth.VaultAuth
import dev.vault.sdk.biometric.VaultBiometric
import dev.vault.sdk.network.APIClient
import dev.vault.sdk.organizations.VaultOrganizations
import dev.vault.sdk.session.VaultSession
import dev.vault.sdk.utils.VaultLogger

/**
 * Main entry point for the Vault Android SDK.
 * 
 * Example usage:
 * ```kotlin
 * // In your Application.onCreate() or MainActivity
 * Vault.configure(
 *     apiUrl = "https://api.vault.dev",
 *     tenantId = "my-tenant"
 * )
 * 
 * // Then use throughout your app
 * val auth = VaultAuth()
 * val session = VaultSession()
 * ```
 */
object Vault {
    
    private var _config: VaultConfig? = null
    private var _context: Context? = null
    private var _isInitialized = false
    
    /**
     * SDK version string
     */
    const val VERSION = BuildConfig.SDK_VERSION
    
    /**
     * Current SDK configuration
     * @throws IllegalStateException if SDK is not initialized
     */
    val config: VaultConfig
        get() = _config ?: throw IllegalStateException(
            "Vault SDK not initialized. Call Vault.configure() first."
        )
    
    /**
     * Application context
     * @throws IllegalStateException if SDK is not initialized
     */
    val context: Context
        get() = _context ?: throw IllegalStateException(
            "Vault SDK not initialized. Call Vault.configure() first."
        )
    
    /**
     * Whether the SDK has been initialized
     */
    val isInitialized: Boolean
        get() = _isInitialized
    
    /**
     * Configure the Vault SDK with required parameters.
     * Should be called once, typically in Application.onCreate() or MainActivity.onCreate()
     * 
     * @param context Application context
     * @param apiUrl Base URL for the Vault API
     * @param tenantId Your tenant identifier
     * @param timeout Request timeout in seconds (default: 30)
     * @param enableLogging Whether to enable debug logging (default: false in release)
     */
    @JvmStatic
    @JvmOverloads
    fun configure(
        context: Context,
        apiUrl: String,
        tenantId: String,
        timeout: Long = 30,
        enableLogging: Boolean = BuildConfig.DEBUG
    ) {
        if (_isInitialized) {
            VaultLogger.w("Vault SDK already initialized. Ignoring duplicate configure() call.")
            return
        }
        
        _context = context.applicationContext
        _config = VaultConfig(
            apiUrl = apiUrl.removeSuffix("/"),
            tenantId = tenantId,
            timeout = timeout
        )
        
        VaultLogger.configure(enableLogging)
        APIClient.initialize(_config!!)
        
        _isInitialized = true
        VaultLogger.i("Vault SDK initialized - v$VERSION")
    }
    
    /**
     * Reset the SDK configuration. Useful for testing or switching tenants.
     */
    @JvmStatic
    fun reset() {
        _config = null
        _context = null
        _isInitialized = false
        APIClient.reset()
        VaultLogger.i("Vault SDK reset")
    }
    
    /**
     * Create a new Auth instance
     */
    @JvmStatic
    fun auth(): VaultAuth = VaultAuth()
    
    /**
     * Create a new Session instance
     */
    @JvmStatic
    fun session(): VaultSession = VaultSession()
    
    /**
     * Create a new Biometric instance
     */
    @JvmStatic
    fun biometric(context: Context): VaultBiometric = VaultBiometric(context)
    
    /**
     * Create a new Organizations instance
     */
    @JvmStatic
    fun organizations(): VaultOrganizations = VaultOrganizations()
}

/**
 * Configuration for the Vault SDK
 */
data class VaultConfig(
    val apiUrl: String,
    val tenantId: String,
    val timeout: Long
) {
    /**
     * Full API base URL including tenant
     */
    val baseUrl: String
        get() = "$apiUrl/v1/tenants/$tenantId"
}
