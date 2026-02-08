/**
 * VaultSdk Native Module for Android
 * 
 * Optional native module for advanced Android functionality.
 * Most features work with the JavaScript layer using existing libraries.
 */

package com.vault.reactnative

import android.content.Context
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import androidx.annotation.RequiresApi
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.facebook.react.bridge.*
import java.util.concurrent.Executor

class VaultSdkModule(reactContext: ReactApplicationContext) : 
  ReactContextBaseJavaModule(reactContext) {

  override fun getName(): String = "VaultSdk"

  /**
   * Get available biometric type
   */
  @ReactMethod
  fun getBiometricType(promise: Promise) {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
      val biometricManager = reactApplicationContext.getSystemService(Context.BIOMETRIC_SERVICE) 
        as BiometricManager
      
      when (biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)) {
        BiometricManager.BIOMETRIC_SUCCESS -> {
          // Check specific biometric type
          val packageManager = reactApplicationContext.packageManager
          val hasFingerprint = packageManager.hasSystemFeature(
            android.content.pm.PackageManager.FEATURE_FINGERPRINT
          )
          val hasFace = packageManager.hasSystemFeature(
            android.content.pm.PackageManager.FEATURE_FACE
          )
          val hasIris = packageManager.hasSystemFeature(
            android.content.pm.PackageManager.FEATURE_IRIS
          )
          
          when {
            hasFace -> promise.resolve("Face")
            hasFingerprint -> promise.resolve("Fingerprint")
            hasIris -> promise.resolve("Iris")
            else -> promise.resolve("Biometric")
          }
        }
        else -> promise.resolve("none")
      }
    } else {
      // Fallback for older Android versions
      val fingerprintManager = reactApplicationContext.getSystemService(Context.FINGERPRINT_SERVICE)
        as? android.hardware.fingerprint.FingerprintManager
      
      if (fingerprintManager?.isHardwareDetected == true) {
        promise.resolve("Fingerprint")
      } else {
        promise.resolve("none")
      }
    }
  }

  /**
   * Check if biometric is enrolled
   */
  @ReactMethod
  fun isBiometricEnrolled(promise: Promise) {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
      val biometricManager = reactApplicationContext.getSystemService(Context.BIOMETRIC_SERVICE)
        as BiometricManager
      
      val canAuthenticate = biometricManager.canAuthenticate(
        BiometricManager.Authenticators.BIOMETRIC_STRONG
      )
      
      promise.resolve(canAuthenticate == BiometricManager.BIOMETRIC_SUCCESS)
    } else {
      // Fallback for older Android versions
      val fingerprintManager = reactApplicationContext.getSystemService(Context.FINGERPRINT_SERVICE)
        as? android.hardware.fingerprint.FingerprintManager
      
      promise.resolve(fingerprintManager?.hasEnrolledFingerprints() == true)
    }
  }

  /**
   * Authenticate with biometrics
   */
  @RequiresApi(Build.VERSION_CODES.P)
  @ReactMethod
  fun authenticate(prompt: String, promise: Promise) {
    val activity = currentActivity as? FragmentActivity
      ?: run {
        promise.reject("ERROR", "Activity not available")
        return
      }

    val executor: Executor = ContextCompat.getMainExecutor(reactApplicationContext)
    
    val biometricPrompt = BiometricPrompt(activity, executor,
      object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(
          result: AuthenticationResult
        ) {
          super.onAuthenticationSucceeded(result)
          promise.resolve(mapOf("success" to true))
        }

        override fun onAuthenticationFailed() {
          super.onAuthenticationFailed()
          promise.resolve(mapOf(
            "success" to false,
            "error" to "Authentication failed"
          ))
        }

        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
          super.onAuthenticationError(errorCode, errString)
          promise.resolve(mapOf(
            "success" to false,
            "error" to errString.toString()
          ))
        }
      })

    val promptInfo = BiometricPrompt.PromptInfo.Builder()
      .setTitle("Authentication Required")
      .setSubtitle(prompt)
      .setNegativeButtonText("Cancel")
      .build()

    biometricPrompt.authenticate(promptInfo)
  }

  /**
   * Check if secure hardware is available
   */
  @ReactMethod
  fun isSecureHardwareAvailable(promise: Promise) {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
      val biometricManager = reactApplicationContext.getSystemService(Context.BIOMETRIC_SERVICE)
        as BiometricManager
      
      val canAuthenticate = biometricManager.canAuthenticate(
        BiometricManager.Authenticators.BIOMETRIC_STRONG
      )
      
      promise.resolve(canAuthenticate == BiometricManager.BIOMETRIC_SUCCESS)
    } else {
      promise.resolve(false)
    }
  }

  companion object {
    const val NAME = "VaultSdk"
  }
}

/**
 * Package for registering the module
 */
class VaultSdkPackage : ReactPackage {
  override fun createNativeModules(
    reactContext: ReactApplicationContext
  ): List<NativeModule> = listOf(VaultSdkModule(reactContext))

  override fun createViewManagers(
    reactContext: ReactApplicationContext
  ): List<ViewManager<*, *>> = emptyList()
}
