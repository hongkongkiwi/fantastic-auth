# VaultAuth Android SDK

Native Android SDK for Vault authentication with support for biometric authentication, push notifications, and pre-built UI components.

## Features

- 🔐 **Secure Authentication** - Email/password login with secure token storage
- 👆 **Biometric Auth** - Fingerprint and Face ID support using Android Keystore
- 📱 **Push Notifications** - MFA push notification support via Firebase
- 🎨 **Pre-built UI** - Ready-to-use login, signup, and profile screens
- 🏢 **Organizations** - Multi-tenant organization support
- 🔒 **MFA Support** - TOTP, SMS, and email-based MFA
- 🚀 **Modern Android** - Coroutines, Flow, Material 3, and Jetpack Compose support

## Installation

Add the dependency to your app's `build.gradle`:

```groovy
dependencies {
    implementation 'com.vault:vaultauth:1.0.0'
    
    // Optional: For biometric auth
    implementation 'androidx.biometric:biometric:1.1.0'
    
    // Optional: For push notifications
    implementation 'com.google.firebase:firebase-messaging:23.4.0'
    
    // Optional: For Jetpack Compose UI
    implementation platform('androidx.compose:compose-bom:2023.10.01')
    implementation 'androidx.compose.ui:ui'
    implementation 'androidx.compose.material3:material3'
}
```

## Quick Start

### 1. Configure the SDK

Initialize the SDK in your `Application` class:

```kotlin
class MyApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        
        VaultAuth.getInstance().configure(
            context = this,
            apiKey = "your_api_key",
            baseUrl = "https://vault.example.com",
            tenantId = "your_tenant_id" // Optional
        )
    }
}
```

### 2. Login

```kotlin
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch

class LoginActivity : AppCompatActivity() {
    
    private fun login(email: String, password: String) {
        lifecycleScope.launch {
            try {
                val user = VaultAuth.getInstance().login(email, password)
                // Success - user is now authenticated
                navigateToHome()
            } catch (e: VaultAuthException) {
                // Handle error
                when (e) {
                    is VaultAuthException.InvalidCredentials -> 
                        showError("Invalid email or password")
                    is VaultAuthException.NetworkError -> 
                        showError("Network error. Please check your connection.")
                    else -> showError(e.message ?: "Unknown error")
                }
            }
        }
    }
}
```

### 3. Check Authentication State

```kotlin
// Check if user is authenticated
if (VaultAuth.getInstance().isAuthenticated) {
    val user = VaultAuth.getInstance().currentUser
    val session = VaultAuth.getInstance().currentSession
}

// Observe auth state changes
lifecycleScope.launch {
    VaultAuth.getInstance().authState?.collect { state ->
        when (state) {
            is AuthState.Authenticated -> {
                // User is logged in
            }
            is AuthState.Unauthenticated -> {
                // User is logged out
            }
            is AuthState.MfaRequired -> {
                // Show MFA screen
            }
            else -> {}
        }
    }
}
```

## Biometric Authentication

### Enable Biometric Login

```kotlin
lifecycleScope.launch {
    try {
        VaultAuth.getInstance().enableBiometricLogin(activity)
        // Biometric login is now enabled
    } catch (e: VaultAuthException.BiometricNotAvailable) {
        // Biometric not available on this device
    }
}
```

### Login with Biometric

```kotlin
lifecycleScope.launch {
    try {
        val user = VaultAuth.getInstance().loginWithBiometric(activity)
        // Successfully logged in
    } catch (e: VaultAuthException.BiometricCancelled) {
        // User cancelled biometric prompt
    }
}
```

## Push Notifications

### Setup Firebase Messaging

1. Add Firebase to your project
2. Create a service that extends `VaultMessagingService`:

```kotlin
class MyMessagingService : VaultMessagingService() {
    // The base class handles token registration and message parsing
}
```

3. Register the service in `AndroidManifest.xml`:

```xml
<service
    android:name=".MyMessagingService"
    android:exported="false">
    <intent-filter>
        <action android:name="com.google.firebase.MESSAGING_EVENT" />
    </intent-filter>
</service>
```

## Pre-built UI Components

### Login Activity

```kotlin
// Start login activity
val intent = VaultLoginActivity.createIntent(context)
startActivityForResult(intent, REQUEST_LOGIN)

// Handle result
override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
    if (requestCode == REQUEST_LOGIN) {
        if (resultCode == RESULT_OK) {
            val user = data?.getParcelableExtra<VaultUserParcelable>(VaultLoginActivity.EXTRA_USER)
            // Login successful
        } else {
            val error = data?.getStringExtra(VaultLoginActivity.EXTRA_ERROR)
            // Login failed
        }
    }
}
```

### Profile Fragment

```kotlin
// Add to your layout
supportFragmentManager.beginTransaction()
    .replace(R.id.container, VaultProfileFragment.newInstance())
    .commit()
```

## Organizations

```kotlin
// Get all organizations
val organizations = VaultAuth.getInstance().getOrganizations()

// Switch organization
VaultAuth.getInstance().switchOrganization("org_id")
```

## Multi-Factor Authentication (MFA)

```kotlin
// Enable MFA
val mfaSetup = VaultAuth.getInstance().enableMfa(MfaMethod.TOTP)
// Display QR code from mfaSetup.qrCode to user

// Verify MFA code during login
VaultAuth.getInstance().verifyMfa(code, MfaMethod.TOTP)

// Disable MFA
VaultAuth.getInstance().disableMfa(MfaMethod.TOTP)
```

## Session Management

```kotlin
// Get all active sessions
val sessions = VaultAuth.getInstance().getSessions()

// Revoke a specific session
VaultAuth.getInstance().revokeSession("session_id")

// Revoke all other sessions
VaultAuth.getInstance().revokeAllOtherSessions()

// Refresh session
VaultAuth.getInstance().refreshSession()
```

## Error Handling

The SDK throws `VaultAuthException` for all errors:

```kotlin
try {
    VaultAuth.getInstance().login(email, password)
} catch (e: VaultAuthException) {
    when (e) {
        is VaultAuthException.InvalidCredentials -> { }
        is VaultAuthException.NetworkError -> { }
        is VaultAuthException.SessionExpired -> { }
        is VaultAuthException.MfaRequired -> { }
        // ... handle other exceptions
    }
    
    // Check if error is retryable
    if (e.isRetryable()) {
        // Retry the operation
    }
}
```

## Security

### Token Storage

Tokens are securely stored using Android Keystore:

```kotlin
// Use default secure storage (encrypted with Android Keystore)
VaultAuth.getInstance().configure(
    context = context,
    apiKey = "api_key",
    baseUrl = "https://vault.example.com"
)

// Or provide custom storage
VaultAuth.getInstance().configure(
    context = context,
    apiKey = "api_key",
    baseUrl = "https://vault.example.com",
    storage = MyCustomStorage()
)
```

### Biometric Protection

Biometric tokens are protected with hardware-backed encryption when available.

## API Reference

### VaultAuth

Main SDK class with singleton pattern.

| Method | Description |
|--------|-------------|
| `configure()` | Initialize the SDK |
| `login()` | Email/password login |
| `loginWithBiometric()` | Biometric authentication |
| `signup()` | Create new account |
| `logout()` | End session |
| `getOrganizations()` | List user's organizations |
| `switchOrganization()` | Change active organization |
| `enableMfa()` / `disableMfa()` | MFA management |
| `getSessions()` | List active sessions |

### Models

- `User` - User account information
- `Session` - Authentication session
- `Organization` - Organization/tenant data
- `MfaMethod` - MFA method types (TOTP, SMS, EMAIL, etc.)

## Sample App

See the `/sample` directory for a complete example app.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Support

- Documentation: https://docs.vault.dev/android
- Issues: https://github.com/vault/android-sdk/issues
