package dev.vault.sdk.biometric

import android.content.Context
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import dev.vault.sdk.utils.VaultLogger
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Biometric authentication result
 */
sealed class BiometricResult {
    data class Success(val cryptoObject: BiometricPrompt.CryptoObject?) : BiometricResult()
    data class Error(val code: Int, val message: String) : BiometricResult()
    object Cancelled : BiometricResult()
}

/**
 * Exception thrown when biometric authentication fails
 */
class BiometricException(message: String, val code: Int = -1) : Exception(message)

/**
 * Biometric authentication manager for Vault
 */
class VaultBiometric(private val context: Context) {
    
    private val biometricManager = BiometricManager.from(context)
    
    companion object {
        const val AUTHENTICATOR_STRONG = BiometricManager.Authenticators.BIOMETRIC_STRONG
        const val AUTHENTICATOR_WEAK = BiometricManager.Authenticators.BIOMETRIC_WEAK
        const val AUTHENTICATOR_DEVICE_CREDENTIAL = BiometricManager.Authenticators.DEVICE_CREDENTIAL
    }
    
    /**
     * Check if biometric authentication is available
     */
    val isAvailable: Boolean
        get() = canAuthenticate(AUTHENTICATOR_STRONG)
    
    /**
     * Check if weak biometric (face recognition without strong security) is available
     */
    val isWeakAvailable: Boolean
        get() = canAuthenticate(AUTHENTICATOR_WEAK)
    
    /**
     * Get detailed availability status
     */
    val availabilityStatus: BiometricStatus
        get() = when (biometricManager.canAuthenticate(AUTHENTICATOR_STRONG)) {
            BiometricManager.BIOMETRIC_SUCCESS -> BiometricStatus.AVAILABLE
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> BiometricStatus.NO_HARDWARE
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> BiometricStatus.HARDWARE_UNAVAILABLE
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> BiometricStatus.NOT_ENROLLED
            BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> BiometricStatus.SECURITY_UPDATE_REQUIRED
            else -> BiometricStatus.UNKNOWN
        }
    
    /**
     * Authenticate with biometric
     * 
     * @param activity FragmentActivity for showing the biometric prompt
     * @param title Title shown in the biometric prompt
     * @param subtitle Optional subtitle
     * @param description Optional description
     * @param negativeButtonText Text for the negative button (cancel)
     * @param allowDeviceCredential Whether to allow device PIN/pattern as fallback
     * @param cryptoObject Optional CryptoObject for cryptographic operations
     * @return BiometricResult
     * @throws BiometricException if authentication fails
     */
    suspend fun authenticate(
        activity: FragmentActivity,
        title: String,
        subtitle: String? = null,
        description: String? = null,
        negativeButtonText: String = "Cancel",
        allowDeviceCredential: Boolean = false,
        cryptoObject: BiometricPrompt.CryptoObject? = null
    ): BiometricResult = suspendCancellableCoroutine { continuation ->
        
        if (!isAvailable && !allowDeviceCredential) {
            continuation.resumeWithException(
                BiometricException("Biometric authentication not available")
            )
            return@suspendCancellableCoroutine
        }
        
        val executor = ContextCompat.getMainExecutor(activity)
        
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                VaultLogger.i("Biometric authentication succeeded")
                continuation.resume(BiometricResult.Success(result.cryptoObject))
            }
            
            override fun onAuthenticationFailed() {
                VaultLogger.w("Biometric authentication failed")
                // Don't resume here - wait for onAuthenticationError
            }
            
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                VaultLogger.e("Biometric error: $errorCode - $errString")
                when (errorCode) {
                    BiometricPrompt.ERROR_USER_CANCELED,
                    BiometricPrompt.ERROR_NEGATIVE_BUTTON -> {
                        continuation.resume(BiometricResult.Cancelled)
                    }
                    BiometricPrompt.ERROR_CANCELED -> {
                        continuation.resume(BiometricResult.Cancelled)
                    }
                    else -> {
                        continuation.resume(
                            BiometricResult.Error(errorCode, errString.toString())
                        )
                    }
                }
            }
        }
        
        val prompt = BiometricPrompt(activity, executor, callback)
        
        val promptInfoBuilder = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setDescription(description)
        
        if (allowDeviceCredential) {
            promptInfoBuilder.setAllowedAuthenticators(
                AUTHENTICATOR_STRONG or AUTHENTICATOR_DEVICE_CREDENTIAL
            )
        } else {
            promptInfoBuilder
                .setNegativeButtonText(negativeButtonText)
                .setAllowedAuthenticators(AUTHENTICATOR_STRONG)
        }
        
        val promptInfo = promptInfoBuilder.build()
        
        continuation.invokeOnCancellation {
            prompt.cancelAuthentication()
        }
        
        if (cryptoObject != null) {
            prompt.authenticate(promptInfo, cryptoObject)
        } else {
            prompt.authenticate(promptInfo)
        }
    }
    
    /**
     * Simple authenticate that returns boolean result
     * 
     * @param activity FragmentActivity for showing the biometric prompt
     * @param title Title shown in the biometric prompt
     * @param subtitle Optional subtitle
     * @return true if authentication succeeded
     */
    suspend fun authenticateSimple(
        activity: FragmentActivity,
        title: String,
        subtitle: String? = null
    ): Boolean {
        return when (val result = authenticate(activity, title, subtitle)) {
            is BiometricResult.Success -> true
            else -> false
        }
    }
    
    /**
     * Generate a key pair for biometric-protected cryptographic operations
     * 
     * @param keyAlias Alias for the key
     * @return Generated KeyPair
     * @throws Exception if key generation fails
     */
    fun generateKeyPair(keyAlias: String = "vault_biometric_key"): java.security.KeyPair {
        return AndroidKeystore.generateBiometricKey(keyAlias)
    }
    
    /**
     * Check if biometric key exists
     * 
     * @param keyAlias Alias for the key
     */
    fun hasKeyPair(keyAlias: String = "vault_biometric_key"): Boolean {
        return AndroidKeystore.hasKey(keyAlias)
    }
    
    /**
     * Delete biometric key
     * 
     * @param keyAlias Alias for the key
     */
    fun deleteKeyPair(keyAlias: String = "vault_biometric_key") {
        AndroidKeystore.deleteKey(keyAlias)
    }
    
    /**
     * Get the crypto object for signing with biometric key
     * Use this with authenticate() for cryptographic operations
     * 
     * @param keyAlias Alias for the key
     * @return CryptoObject configured for signing
     */
    fun getCryptoObject(keyAlias: String = "vault_biometric_key"): BiometricPrompt.CryptoObject? {
        return try {
            val signature = AndroidKeystore.getSignatureInstance(keyAlias)
            BiometricPrompt.CryptoObject(signature)
        } catch (e: Exception) {
            VaultLogger.e("Failed to create crypto object: ${e.message}")
            null
        }
    }
    
    private fun canAuthenticate(authenticators: Int): Boolean {
        return biometricManager.canAuthenticate(authenticators) == BiometricManager.BIOMETRIC_SUCCESS
    }
}

/**
 * Biometric availability status
 */
enum class BiometricStatus {
    AVAILABLE,
    NO_HARDWARE,
    HARDWARE_UNAVAILABLE,
    NOT_ENROLLED,
    SECURITY_UPDATE_REQUIRED,
    UNKNOWN
}
