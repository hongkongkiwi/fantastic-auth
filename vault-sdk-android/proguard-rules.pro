# ProGuard rules for Vault SDK

# Keep public API
-keep public class dev.vault.sdk.** {
    public *;
}

# Keep data classes
-keepclassmembers class dev.vault.sdk.** {
    *** get*();
    void set*(***);
}

# Keep Serializable/Parcelable
-keepnames class * implements android.os.Parcelable
-keepnames class * implements java.io.Serializable

# Gson
-keepattributes Signature
-keepattributes *Annotation*
-dontwarn sun.misc.**
-keep class com.google.gson.** { *; }
-keep class * extends com.google.gson.TypeAdapter
-keep class * implements com.google.gson.TypeAdapterFactory
-keep class * implements com.google.gson.JsonSerializer
-keep class * implements com.google.gson.JsonDeserializer

# OkHttp
-dontwarn okhttp3.**
-dontwarn okio.**
-dontwarn javax.annotation.**
-keepnames class okhttp3.internal.publicsuffix.PublicSuffixDatabase

# Kotlin Coroutines
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory {}
-keepnames class kotlinx.coroutines.CoroutineExceptionHandler {}
-keepnames class kotlinx.coroutines.android.AndroidExceptionPreHandler {}
-keepnames class kotlinx.coroutines.android.AndroidDispatcherFactory {}

# Biometric
-keep class androidx.biometric.** { *; }

# EncryptedSharedPreferences
-keep class androidx.security.crypto.** { *; }
