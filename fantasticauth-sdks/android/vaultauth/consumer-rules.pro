# VaultAuth SDK ProGuard Rules

# Keep model classes for Gson serialization
-keep class com.vault.models.** { *; }
-keepclassmembers class com.vault.models.** { *; }

# Keep VaultAuth public API
-keep public class com.vault.VaultAuth { *; }
-keep public class com.vault.VaultClient { *; }
-keep public class com.vault.VaultConfig { *; }
-keep public class com.vault.AuthState { *; }

# Keep storage interfaces
-keep public interface com.vault.storage.TokenStorage { *; }
-keep public class com.vault.storage.KeystoreStorage { *; }

# Keep biometric classes
-keep public class com.vault.biometric.BiometricAuth { *; }
-keep public enum com.vault.biometric.BiometricType { *; }
-keep public class com.vault.biometric.BiometricError { *; }

# Keep push notification classes
-keep public class com.vault.push.VaultMessagingService { *; }
-keep public class com.vault.push.PushNotificationManager { *; }

# Keep UI classes
-keep public class com.vault.ui.VaultLoginActivity { *; }
-keep public class com.vault.ui.VaultSignupActivity { *; }
keep public class com.vault.ui.VaultProfileFragment { *; }
-keep public class com.vault.ui.VaultUserParcelable { *; }

# Keep exception classes
-keep public class com.vault.models.VaultAuthException { *; }

# Retrofit
-keepattributes Signature
-keepattributes *Annotation*
-dontwarn retrofit2.**
-keep class retrofit2.** { *; }
-keepclasseswithmembers class * {
    @retrofit2.http.* <methods>;
}

# OkHttp
-dontwarn okhttp3.**
-dontwarn okio.**
-keep class okhttp3.** { *; }

# Gson
-keepattributes EnclosingMethod
-keep class com.google.gson.** { *; }

# AndroidX Security
-keep class androidx.security.** { *; }

# Coroutines
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory {}
-keepnames class kotlinx.coroutines.CoroutineExceptionHandler {}
