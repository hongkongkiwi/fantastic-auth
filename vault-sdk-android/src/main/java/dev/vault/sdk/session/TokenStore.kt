package dev.vault.sdk.session

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import dev.vault.sdk.biometric.AndroidKeystore
import dev.vault.sdk.utils.VaultLogger
import java.security.KeyPair
import java.util.Date

/**
 * Secure token storage using Android Keystore and EncryptedSharedPreferences
 */
internal class TokenStore(context: Context) {
    
    private val prefs: SharedPreferences
    private val biometricKeyAlias = "vault_biometric_key"
    
    companion object {
        private const val PREFS_FILE = "vault_secure_tokens"
        private const val KEY_ACCESS_TOKEN = "access_token"
        private const val KEY_REFRESH_TOKEN = "refresh_token"
        private const val KEY_TOKEN_EXPIRY = "token_expiry"
        private const val KEY_BIOMETRIC_ENABLED = "biometric_enabled"
        private const val KEY_BIOMETRIC_KEY_ID = "biometric_key_id"
    }
    
    init {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        
        prefs = EncryptedSharedPreferences.create(
            context,
            PREFS_FILE,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }
    
    /**
     * Save authentication tokens securely
     * 
     * @param accessToken JWT access token
     * @param refreshToken Refresh token
     * @param expiresIn Token expiry in seconds (optional)
     */
    fun saveTokens(
        accessToken: String,
        refreshToken: String,
        expiresIn: Long? = null
    ) {
        prefs.edit().apply {
            putString(KEY_ACCESS_TOKEN, accessToken)
            putString(KEY_REFRESH_TOKEN, refreshToken)
            expiresIn?.let {
                val expiryTime = System.currentTimeMillis() + (it * 1000)
                putLong(KEY_TOKEN_EXPIRY, expiryTime)
            }
            apply()
        }
        VaultLogger.d("Tokens saved securely")
    }
    
    /**
     * Get the stored access token
     * 
     * @return Access token or null if not stored
     */
    fun getAccessToken(): String? {
        return prefs.getString(KEY_ACCESS_TOKEN, null)
    }
    
    /**
     * Get the stored refresh token
     * 
     * @return Refresh token or null if not stored
     */
    fun getRefreshToken(): String? {
        return prefs.getString(KEY_REFRESH_TOKEN, null)
    }
    
    /**
     * Get token expiry time
     * 
     * @return Expiry date or null if not set
     */
    fun getTokenExpiry(): Date? {
        val expiry = prefs.getLong(KEY_TOKEN_EXPIRY, 0)
        return if (expiry > 0) Date(expiry) else null
    }
    
    /**
     * Check if token is expired or about to expire
     * 
     * @param bufferSeconds Seconds buffer before actual expiry (default: 60)
     * @return true if token is expired or expiring soon
     */
    fun isTokenExpired(bufferSeconds: Long = 60): Boolean {
        val expiry = getTokenExpiry() ?: return true
        return Date().time > (expiry.time - (bufferSeconds * 1000))
    }
    
    /**
     * Clear all stored tokens
     */
    fun clearTokens() {
        prefs.edit().apply {
            remove(KEY_ACCESS_TOKEN)
            remove(KEY_REFRESH_TOKEN)
            remove(KEY_TOKEN_EXPIRY)
            apply()
        }
        VaultLogger.d("Tokens cleared")
    }
    
    /**
     * Enable biometric authentication
     * Generates a key pair that requires biometric authentication
     */
    fun enableBiometricKey() {
        try {
            val keyPair = AndroidKeystore.generateBiometricKey(biometricKeyAlias)
            prefs.edit().apply {
                putBoolean(KEY_BIOMETRIC_ENABLED, true)
                putString(KEY_BIOMETRIC_KEY_ID, keyPair.public.hashCode().toString())
                apply()
            }
            VaultLogger.i("Biometric authentication enabled")
        } catch (e: Exception) {
            VaultLogger.e("Failed to enable biometric: ${e.message}")
            throw e
        }
    }
    
    /**
     * Check if biometric authentication is enabled
     */
    fun isBiometricEnabled(): Boolean {
        return prefs.getBoolean(KEY_BIOMETRIC_ENABLED, false) &&
               AndroidKeystore.hasKey(biometricKeyAlias)
    }
    
    /**
     * Get biometric key information for authentication
     */
    fun getBiometricKey(): BiometricKeyInfo? {
        if (!isBiometricEnabled()) return null
        
        val keyId = prefs.getString(KEY_BIOMETRIC_KEY_ID, null)
            ?: return null
        
        return BiometricKeyInfo(
            keyId = keyId,
            keyAlias = biometricKeyAlias
        )
    }
    
    /**
     * Disable biometric authentication
     */
    fun disableBiometric() {
        AndroidKeystore.deleteKey(biometricKeyAlias)
        prefs.edit().apply {
            putBoolean(KEY_BIOMETRIC_ENABLED, false)
            remove(KEY_BIOMETRIC_KEY_ID)
            apply()
        }
        VaultLogger.i("Biometric authentication disabled")
    }
    
    /**
     * Clear all stored data including biometric keys
     */
    fun clearAll() {
        clearTokens()
        disableBiometric()
        prefs.edit().clear().apply()
        VaultLogger.d("All token store data cleared")
    }
}

/**
 * Biometric key information
 */
data class BiometricKeyInfo(
    val keyId: String,
    private val keyAlias: String
) {
    /**
     * Create a signature using the biometric-protected key
     * This will trigger biometric authentication
     * 
     * @return Base64-encoded signature
     */
    fun createSignature(): String {
        return AndroidKeystore.signWithKey(keyAlias, keyId.toByteArray())
    }
}
