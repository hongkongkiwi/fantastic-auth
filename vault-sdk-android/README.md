# Vault Android SDK

Native Android SDK for Vault identity and access management. Built with Kotlin coroutines, biometric authentication, and secure hardware-backed storage.

## Installation

### Gradle

```kotlin
dependencies {
    implementation("dev.vault:vault-sdk-android:1.0.0")
}
```

### Requirements

- minSdk: 26 (Android 8.0)
- targetSdk: 34
- Kotlin: 1.9+

## Quick Start

### 1. Initialize

```kotlin
// In your Application.onCreate()
Vault.configure(
    context = this,
    apiUrl = "https://api.vault.dev",
    tenantId = "my-tenant",
    enableLogging = BuildConfig.DEBUG
)
```

### 2. Sign In

```kotlin
val auth = Vault.auth()

lifecycleScope.launch {
    try {
        val session = auth.signIn(
            email = "user@example.com",
            password = "password"
        )
        println("Signed in: ${session.user.email}")
    } catch (e: VaultException) {
        println("Error: ${e.message}")
    }
}
```

### 3. Biometric Authentication

```kotlin
val biometric = Vault.biometric(activity)

if (biometric.isAvailable) {
    lifecycleScope.launch {
        val success = biometric.authenticateSimple(
            activity = this@MainActivity,
            title = "Sign in to Vault",
            subtitle = "Use your fingerprint"
        )
        
        if (success) {
            val session = auth.signInWithBiometric()
        }
    }
}
```

## Features

### 🔐 Authentication

- Email/password sign-in
- Biometric authentication
- Magic links (passwordless)
- OAuth (Google, Apple, GitHub, Microsoft)
- Session management

### 👤 User Management

```kotlin
val profile = VaultUserProfile()

// Get current user
val user = profile.getCurrentUser()

// Update profile
profile.updateProfile(
    Profile(name = "New Name", avatar = "...")
)

// Change password
profile.changePassword(
    currentPassword = "old",
    newPassword = "new",
    revokeOtherSessions = true
)
```

### 🏢 Organizations (B2B)

```kotlin
val orgs = Vault.organizations()

// List organizations
val organizations = orgs.list()

// Create organization
val org = orgs.create(name = "Acme Corp")

// Set active organization
orgs.setActive(org.id)

// Manage members
orgs.inviteMember(
    orgId = org.id,
    email = "colleague@acme.com",
    role = OrganizationRole.ADMIN
)
```

### 🔒 Secure Storage

Tokens are stored using:
- **EncryptedSharedPreferences** - AES-256 encrypted
- **Android Keystore** - Hardware-backed keys (when available)
- **Biometric binding** - Keys tied to biometric authentication

### 📡 Reactive UI

```kotlin
// Observe current user
VaultSession.currentUserFlow.collect { user ->
    if (user != null) {
        // User is signed in
        updateUI(user)
    } else {
        // User is signed out
        showSignIn()
    }
}

// Observe active organization
VaultOrganizations.activeOrganizationFlow.collect { org ->
    updateOrgUI(org)
}
```

## API Reference

### Vault

```kotlin
// Configuration
Vault.configure(context, apiUrl, tenantId)
Vault.reset()

// Factories
Vault.auth(): VaultAuth
Vault.session(): VaultSession
Vault.biometric(context): VaultBiometric
Vault.organizations(): VaultOrganizations
```

### VaultAuth

```kotlin
suspend fun signIn(email: String, password: String): SessionData
suspend fun signUp(email: String, password: String, name: String?): SessionData
suspend fun signInWithBiometric(): SessionData
suspend fun requestMagicLink(email: String)
suspend fun signInWithMagicLink(token: String): SessionData
suspend fun forgotPassword(email: String)
suspend fun resetPassword(token: String, newPassword: String)
suspend fun signOut(revokeAll: Boolean = false)
```

### VaultSession

```kotlin
val isAuthenticated: Boolean
val currentUser: User?
val currentSession: SessionData?
fun getToken(): String?
suspend fun restoreSession(): Boolean
suspend fun refreshToken(): Boolean
suspend fun refreshUser(): User
suspend fun signOut(revokeAll: Boolean = false)
```

### VaultBiometric

```kotlin
val isAvailable: Boolean
val availabilityStatus: BiometricStatus

suspend fun authenticate(
    activity: FragmentActivity,
    title: String,
    subtitle: String? = null,
    description: String? = null,
    negativeButtonText: String = "Cancel",
    allowDeviceCredential: Boolean = false,
    cryptoObject: BiometricPrompt.CryptoObject? = null
): BiometricResult

suspend fun authenticateSimple(
    activity: FragmentActivity,
    title: String,
    subtitle: String? = null
): Boolean

fun generateKeyPair(keyAlias: String = "vault_biometric_key"): KeyPair
fun hasKeyPair(keyAlias: String = "vault_biometric_key"): Boolean
```

### VaultOAuth

```kotlin
suspend fun signInWith(
    activity: Activity,
    provider: OAuthProvider,
    scopes: List<String> = emptyList()
): SessionData

suspend fun linkProvider(activity: Activity, provider: OAuthProvider)
suspend fun unlinkProvider(provider: OAuthProvider)
suspend fun getLinkedProviders(): List<String>
```

## Error Handling

```kotlin
lifecycleScope.launch {
    try {
        auth.signIn(email, password)
    } catch (e: VaultException) {
        when {
            e.isAuthError -> showAuthError()
            e.isNetworkError -> showNetworkError()
            e.isRateLimitError -> showRateLimitError()
            else -> showGenericError(e.toUserMessage())
        }
    }
}
```

## Jetpack Compose Integration

```kotlin
@Composable
fun AuthScreen() {
    val session = Vault.session()
    val user by VaultSession.currentUserFlow.collectAsState()
    
    if (user == null) {
        SignInScreen(
            onSignIn = { email, password ->
                coroutineScope.launch {
                    try {
                        Vault.auth().signIn(email, password)
                    } catch (e: VaultException) {
                        // Handle error
                    }
                }
            }
        )
    } else {
        HomeScreen(user = user!!)
    }
}
```

## ProGuard / R8

The SDK includes ProGuard rules. No additional configuration needed.

## License

MIT License - see LICENSE file for details.

## Support

- Documentation: https://docs.vault.dev
- Support: support@vault.dev
- Issues: https://github.com/vault/vault-sdk-android/issues
