package com.vault.biometric

import android.content.Context
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.vault.models.VaultAuthException
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Type of biometric available on the device
 */
enum class BiometricType {
    NONE,
    FINGERPRINT,
    FACE,
    IRIS,
    MULTIPLE
}

/**
 * Biometric authentication error
 */
sealed class BiometricError(val code: Int, message: String) : Exception(message) {
    class HardwareUnavailable : BiometricError(
        BiometricPrompt.ERROR_HW_UNAVAILABLE,
        "Biometric hardware is unavailable"
    )
    class NoHardware : BiometricError(
        BiometricPrompt.ERROR_NO_BIOMETRICS,
        "No biometric hardware available"
    )
    class NotEnrolled : BiometricError(
        BiometricPrompt.ERROR_NO_BIOMETRICS,
        "No biometric credentials enrolled"
    )
    class Cancelled : BiometricError(
        BiometricPrompt.ERROR_USER_CANCELED,
        "Biometric authentication was cancelled"
    )
    class Lockout : BiometricError(
        BiometricPrompt.ERROR_LOCKOUT,
        "Too many failed attempts. Try again later."
    )
    class LockoutPermanent : BiometricError(
        BiometricPrompt.ERROR_LOCKOUT_PERMANENT,
        "Biometric authentication is permanently locked"
    )
    class Failed : BiometricError(
        BiometricPrompt.ERROR_NO_SPACE,
        "Biometric authentication failed"
    )
    class Unknown(code: Int, message: String) : BiometricError(code, message)
}

/**
 * Biometric authentication manager
 * Handles fingerprint and face unlock authentication
 */
class BiometricAuth(private val activity: FragmentActivity) {

    private val biometricManager = BiometricManager.from(activity)
    private val executor = ContextCompat.getMainExecutor(activity)

    /**
     * Check if biometric authentication is available on this device
     */
    val isAvailable: Boolean
        get() = canAuthenticate() == BiometricManager.BIOMETRIC_SUCCESS

    /**
     * Get the type of biometric available
     */
    val biometricType: BiometricType
        get() {
            val authenticators = BiometricManager.Authenticators.BIOMETRIC_WEAK
            return when (biometricManager.canAuthenticate(authenticators)) {
                BiometricManager.BIOMETRIC_SUCCESS -> detectBiometricType()
                else -> BiometricType.NONE
            }
        }

    /**
     * Check if biometric authentication can be used
     */
    fun canAuthenticate(): Int {
        return biometricManager.canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_WEAK
        )
    }

    /**
     * Check if strong biometric (Class 3) is available
     */
    fun canAuthenticateStrong(): Boolean {
        return biometricManager.canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG
        ) == BiometricManager.BIOMETRIC_SUCCESS
    }

    /**
     * Authenticate using biometric
     * 
     * @param title The title shown in the biometric prompt
     * @param subtitle Optional subtitle
     * @param description Optional description
     * @param negativeButtonText Text for the negative button (e.g., "Cancel" or "Use Password")
     * @param onSuccess Callback when authentication succeeds
     * @param onError Callback when authentication fails
     */
    fun authenticate(
        title: String,
        subtitle: String? = null,
        description: String? = null,
        negativeButtonText: String = "Cancel",
        onSuccess: () -> Unit,
        onError: (error: BiometricError) -> Unit
    ) {
        if (!isAvailable) {
            onError(BiometricError.NoHardware())
            return
        }

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setDescription(description)
            .setNegativeButtonText(negativeButtonText)
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_WEAK)
            .build()

        val biometricPrompt = BiometricPrompt(
            activity,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: AuthenticationResult) {
                    onSuccess()
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    onError(mapErrorCode(errorCode, errString.toString()))
                }

                override fun onAuthenticationFailed() {
                    // Don't call onError here, let the system handle retries
                }
            }
        )

        biometricPrompt.authenticate(promptInfo)
    }

    /**
     * Authenticate using biometric (coroutine version)
     * 
     * @param title The title shown in the biometric prompt
     * @param subtitle Optional subtitle
     * @param description Optional description
     * @param negativeButtonText Text for the negative button
     */
    suspend fun authenticate(
        title: String,
        subtitle: String? = null,
        description: String? = null,
        negativeButtonText: String = "Cancel"
    ) = suspendCancellableCoroutine { continuation ->
        if (!isAvailable) {
            continuation.resumeWithException(BiometricError.NoHardware())
            return@suspendCancellableCoroutine
        }

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setDescription(description)
            .setNegativeButtonText(negativeButtonText)
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_WEAK)
            .build()

        val biometricPrompt = BiometricPrompt(
            activity,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: AuthenticationResult) {
                    continuation.resume(Unit)
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    continuation.resumeWithException(mapErrorCode(errorCode, errString.toString()))
                }

                override fun onAuthenticationFailed() {
                    // Don't resume here, let the system handle retries
                }
            }
        )

        biometricPrompt.authenticate(promptInfo)

        continuation.invokeOnCancellation {
            // Cancel the authentication if the coroutine is cancelled
            biometricPrompt.cancelAuthentication()
        }
    }

    /**
     * Enable biometric login for the current session
     * This stores a biometric-protected token for future logins
     */
    suspend fun enableBiometricLogin() {
        if (!isAvailable) {
            throw VaultAuthException.BiometricNotAvailable()
        }

        authenticate(
            title = "Enable Biometric Login",
            subtitle = "Verify your identity to enable biometric login",
            description = "You'll be able to log in using your biometric credentials in the future."
        )

        // The actual token storage is handled by VaultAuth after successful authentication
    }

    /**
     * Disable biometric login
     */
    suspend fun disableBiometricLogin() {
        // This is handled by VaultAuth clearing the biometric token
    }

    private fun detectBiometricType(): BiometricType {
        val packageManager = activity.packageManager
        
        val hasFingerprint = packageManager.hasSystemFeature(
            android.content.pm.PackageManager.FEATURE_FINGERPRINT
        )
        val hasFace = packageManager.hasSystemFeature(
            android.content.pm.PackageManager.FEATURE_FACE
        )
        val hasIris = packageManager.hasSystemFeature(
            android.content.pm.PackageManager.FEATURE_IRIS
        )

        return when {
            hasFace && hasFingerprint -> BiometricType.MULTIPLE
            hasIris && hasFingerprint -> BiometricType.MULTIPLE
            hasFace && hasIris -> BiometricType.MULTIPLE
            hasFace -> BiometricType.FACE
            hasIris -> BiometricType.IRIS
            hasFingerprint -> BiometricType.FINGERPRINT
            else -> BiometricType.NONE
        }
    }

    private fun mapErrorCode(code: Int, message: String): BiometricError {
        return when (code) {
            BiometricPrompt.ERROR_HW_UNAVAILABLE -> BiometricError.HardwareUnavailable()
            BiometricPrompt.ERROR_UNABLE_TO_PROCESS,
            BiometricPrompt.ERROR_NO_BIOMETRICS -> BiometricError.NotEnrolled()
            BiometricPrompt.ERROR_HW_NOT_PRESENT -> BiometricError.NoHardware()
            BiometricPrompt.ERROR_NEGATIVE_BUTTON,
            BiometricPrompt.ERROR_USER_CANCELED -> BiometricError.Cancelled()
            BiometricPrompt.ERROR_LOCKOUT -> BiometricError.Lockout()
            BiometricPrompt.ERROR_LOCKOUT_PERMANENT -> BiometricError.LockoutPermanent()
            else -> BiometricError.Unknown(code, message)
        }
    }

    companion object {
        /**
         * Check if biometric authentication is available on the device (static method)
         */
        @JvmStatic
        fun isAvailable(context: Context): Boolean {
            val biometricManager = BiometricManager.from(context)
            return biometricManager.canAuthenticate(
                BiometricManager.Authenticators.BIOMETRIC_WEAK
            ) == BiometricManager.BIOMETRIC_SUCCESS
        }

        /**
         * Get the biometric type available (static method)
         */
        @JvmStatic
        fun getBiometricType(context: Context): BiometricType {
            val biometricManager = BiometricManager.from(context)
            val packageManager = context.packageManager
            
            if (biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_WEAK) 
                != BiometricManager.BIOMETRIC_SUCCESS) {
                return BiometricType.NONE
            }

            val hasFingerprint = packageManager.hasSystemFeature(
                android.content.pm.PackageManager.FEATURE_FINGERPRINT
            )
            val hasFace = packageManager.hasSystemFeature(
                android.content.pm.PackageManager.FEATURE_FACE
            )
            val hasIris = packageManager.hasSystemFeature(
                android.content.pm.PackageManager.FEATURE_IRIS
            )

            return when {
                hasFace && hasFingerprint -> BiometricType.MULTIPLE
                hasIris && hasFingerprint -> BiometricType.MULTIPLE
                hasFace && hasIris -> BiometricType.MULTIPLE
                hasFace -> BiometricType.FACE
                hasIris -> BiometricType.IRIS
                hasFingerprint -> BiometricType.FINGERPRINT
                else -> BiometricType.NONE
            }
        }
    }
}
