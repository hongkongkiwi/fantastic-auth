package dev.vault.sdk

import androidx.annotation.NonNull
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity

import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result

/** VaultSdkPlugin */
class VaultSdkPlugin: FlutterPlugin, MethodCallHandler {
  private lateinit var channel : MethodChannel
  private var activity: FragmentActivity? = null

  override fun onAttachedToEngine(flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
    channel = MethodChannel(flutterPluginBinding.binaryMessenger, "vault_sdk")
    channel.setMethodCallHandler(this)
    
    // Try to get activity from binding
    if (flutterPluginBinding.platformViewRegistry is FragmentActivity) {
      activity = flutterPluginBinding.platformViewRegistry as FragmentActivity
    }
  }

  override fun onMethodCall(call: MethodCall, result: Result) {
    when (call.method) {
      "getPlatformVersion" -> {
        result.success("Android ${android.os.Build.VERSION.RELEASE}")
      }
      "isBiometricAvailable" -> {
        isBiometricAvailable(result)
      }
      "getBiometricType" -> {
        getBiometricType(result)
      }
      "authenticateWithBiometrics" -> {
        val reason = call.argument<String>("reason") ?: "Authenticate"
        authenticateWithBiometrics(reason, result)
      }
      else -> {
        result.notImplemented()
      }
    }
  }

  private fun isBiometricAvailable(result: Result) {
    val activity = this.activity ?: run {
      result.error("NO_ACTIVITY", "Plugin not attached to an activity", null)
      return
    }

    val biometricManager = BiometricManager.from(activity)
    val canAuthenticate = biometricManager.canAuthenticate(
      BiometricManager.Authenticators.BIOMETRIC_STRONG
    )
    
    result.success(canAuthenticate == BiometricManager.BIOMETRIC_SUCCESS)
  }

  private fun getBiometricType(result: Result) {
    val activity = this.activity ?: run {
      result.error("NO_ACTIVITY", "Plugin not attached to an activity", null)
      return
    }

    val biometricManager = BiometricManager.from(activity)
    val canAuthenticate = biometricManager.canAuthenticate(
      BiometricManager.Authenticators.BIOMETRIC_STRONG
    )

    when (canAuthenticate) {
      BiometricManager.BIOMETRIC_SUCCESS -> {
        // Check if device has face or fingerprint
        val packageManager = activity.packageManager
        val hasFingerprint = packageManager.hasSystemFeature(
          android.content.pm.PackageManager.FEATURE_FINGERPRINT
        )
        val hasFace = packageManager.hasSystemFeature(
          android.content.pm.PackageManager.FEATURE_FACE
        )
        
        when {
          hasFace -> result.success("face")
          hasFingerprint -> result.success("fingerprint")
          else -> result.success("biometric")
        }
      }
      else -> result.success("none")
    }
  }

  private fun authenticateWithBiometrics(reason: String, result: Result) {
    val activity = this.activity ?: run {
      result.error("NO_ACTIVITY", "Plugin not attached to an activity", null)
      return
    }

    val executor = ContextCompat.getMainExecutor(activity)
    val biometricPrompt = BiometricPrompt(
      activity,
      executor,
      object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(
          authenticationResult: BiometricPrompt.AuthenticationResult
        ) {
          result.success(true)
        }

        override fun onAuthenticationFailed() {
          result.success(false)
        }

        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
          result.error(
            "AUTHENTICATION_ERROR",
            errString.toString(),
            errorCode
          )
        }
      }
    )

    val promptInfo = BiometricPrompt.PromptInfo.Builder()
      .setTitle("Biometric Authentication")
      .setSubtitle(reason)
      .setNegativeButtonText("Cancel")
      .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
      .build()

    biometricPrompt.authenticate(promptInfo)
  }

  override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
    channel.setMethodCallHandler(null)
  }
}
