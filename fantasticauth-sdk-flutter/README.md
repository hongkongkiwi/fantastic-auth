# Vault SDK for Flutter

A comprehensive Flutter SDK for [Vault](https://github.com/yourorg/vault) - a secure, quantum-resistant user authentication and management system.

## Features

- 🔐 **Multiple Authentication Methods**: Email/password, OAuth (Google, Apple, GitHub), Magic Links, SSO
- 🛡️ **Secure Storage**: iOS Keychain and Android Keystore integration
- 👆 **Biometric Authentication**: Face ID, Touch ID, Fingerprint support
- 🏢 **Organization Management**: Team/organization support with RBAC
- 🔄 **Session Management**: Automatic token refresh, multi-device sessions
- 📱 **Cross-Platform**: iOS and Android support
- ⚡ **Easy Integration**: Simple, intuitive API

## Installation

Add to your `pubspec.yaml`:

```yaml
dependencies:
  vault_sdk: ^0.1.0
```

Or install via command line:

```bash
flutter pub add vault_sdk
```

## Platform Setup

### iOS

Add the following to your `ios/Runner/Info.plist`:

```xml
<!-- Face ID / Touch ID -->
<key>NSFaceIDUsageDescription</key>
<string>Authenticate to access your account securely</string>

<!-- URL Launcher (for OAuth) -->
<key>LSApplicationQueriesSchemes</key>
<array>
    <string>https</string>
    <string>http</string>
</array>
```

### Android

Add the following to your `android/app/src/main/AndroidManifest.xml`:

```xml
<uses-permission android:name="android.permission.USE_BIOMETRIC" />
<uses-permission android:name="android.permission.USE_FINGERPRINT" />

<!-- For URL Launcher -->
<queries>
    <intent>
        <action android:name="android.intent.action.VIEW" />
        <data android:scheme="https" />
    </intent>
</queries>
```

## Quick Start

### 1. Initialize the SDK

```dart
import 'package:vault_sdk/vault.dart';

void main() {
  Vault.initialize(
    apiUrl: 'https://api.vault.dev',
    tenantId: 'my-tenant', // Optional for multi-tenancy
  );
  
  runApp(MyApp());
}
```

### 2. Sign In with Email/Password

```dart
final auth = VaultAuth();

try {
  final result = await auth.signInWithEmail(
    email: 'user@example.com',
    password: 'your-password',
  );
  
  if (result.success) {
    print('Welcome, ${result.user!.email}!');
  } else if (result.mfaRequired) {
    // Handle MFA
    _showMfaInput(result.availableMethods);
  }
} on VaultAuthException catch (e) {
  print('Sign in failed: ${e.message}');
}
```

### 3. Access Current User

```dart
final session = VaultSession();

// Get current user
final user = await session.getCurrentUser();
print(user?.email);

// Check if authenticated
if (await session.isAuthenticated()) {
  // User is signed in
}

// Listen to session changes
session.stateStream.listen((state) {
  if (state == SessionState.unauthenticated) {
    // User signed out
  }
});
```

### 4. Sign Out

```dart
await session.signOut();
```

## Authentication Methods

### Email/Password

```dart
// Sign up
await auth.signUp(
  email: 'new@example.com',
  password: 'secure-password',
  name: 'John Doe',
);

// Sign in
await auth.signInWithEmail(
  email: 'user@example.com',
  password: 'your-password',
);

// Reset password
await auth.sendPasswordResetEmail('user@example.com');
await auth.resetPassword(token: 'reset-token', newPassword: 'new-password');
```

### OAuth

```dart
// Initiate OAuth sign-in
await auth.signInWithOAuth(provider: OAuthProvider.google);

// Handle OAuth callback (in your deep link handler)
void handleDeepLink(Uri uri) {
  if (auth.isOAuthCallback(uri)) {
    final result = auth.extractOAuthResult(uri);
    if (result?.success == true) {
      auth.handleOAuthCallback(
        provider: OAuthProvider.google,
        code: result!.code!,
        state: result.state!,
      );
    }
  }
}
```

### Magic Links

```dart
// Send magic link
await auth.sendMagicLink('user@example.com');

// Verify magic link token
final result = await auth.verifyMagicLink(token);
```

### Biometric Authentication

```dart
final biometric = VaultBiometric();

// Check availability
if (await biometric.isAvailable()) {
  // Authenticate
  final success = await biometric.authenticate(
    reason: 'Verify your identity',
  );
}

// Enable biometric login
await biometric.enableBiometricLogin();

// Sign in with biometrics
final session = await biometric.authenticateWithBiometrics();
```

## Session Management

```dart
final session = VaultSession();

// Get access token
final token = await session.getToken();

// Get current user
final user = await session.getCurrentUser();

// List active sessions
final sessions = await session.listSessions();

// Revoke specific session
await session.revokeSession(sessionId);

// Sign out from all devices
await session.signOutAllDevices();
```

## Organization Management

```dart
final orgs = VaultOrganizations();

// List organizations
final list = await orgs.list();

// Create organization
final org = await orgs.create(
  name: 'My Team',
  slug: 'my-team',
);

// Invite members
await orgs.inviteMember(
  org.id,
  email: 'colleague@example.com',
  role: OrganizationRole.member,
);

// List members
final members = await orgs.listMembers(org.id);

// Update member role
await orgs.updateMember(org.id, userId, role: OrganizationRole.admin);
```

## Multi-Factor Authentication (MFA)

```dart
// Get MFA status
final status = await auth.getMfaStatus();

// Enable TOTP MFA
final setup = await auth.enableMfa(MfaMethod.totp);
if (setup.isTotp) {
  // Show QR code: setup.qrCodeUri
  // Store backup codes: setup.backupCodes
}

// Confirm TOTP setup with verification code
await auth.enableMfa(MfaMethod.totp, code: '123456');

// Disable MFA
await auth.disableMfa('current-mfa-code');

// Generate backup codes
final codes = await auth.generateBackupCodes();
```

## Error Handling

The SDK provides specific exception types for different error scenarios:

```dart
try {
  await auth.signInWithEmail(email: email, password: password);
} on VaultAuthException catch (e) {
  // Authentication failed
  print('Auth error: ${e.message}');
} on VaultNetworkException catch (e) {
  // Network error
  print('Network error: ${e.message}');
} on VaultRateLimitException catch (e) {
  // Rate limited
  print('Rate limited. Retry after ${e.secondsUntilReset}s');
} on VaultMfaRequiredException catch (e) {
  // MFA required
  print('MFA required. Methods: ${e.availableMethods}');
} on VaultException catch (e) {
  // General Vault error
  print('Error: ${e.message}');
}
```

## Configuration Options

```dart
Vault.initialize(
  apiUrl: 'https://api.vault.dev',
  tenantId: 'my-tenant',
  tenantSlug: 'my-tenant', // Alternative to tenantId
  apiVersion: 'v1',
  timeout: Duration(seconds: 30),
  storageOptions: VaultStorageOptions.secure,
  httpClient: MyCustomHttpClient(), // Optional custom HTTP client
);
```

## Storage Security

The SDK uses platform-specific secure storage:

- **iOS**: Keychain with configurable accessibility
- **Android**: EncryptedSharedPreferences or Keystore

```dart
// Custom storage options
Vault.initialize(
  apiUrl: 'https://api.vault.dev',
  storageOptions: VaultStorageOptions(
    androidOptions: AndroidOptions(
      encryptedSharedPreferences: true,
    ),
    iosOptions: IOSOptions(
      accessibility: KeychainAccessibility.when_unlocked,
    ),
  ),
);
```

## Complete Example

See the [example](example/main.dart) directory for a complete Flutter app demonstrating all SDK features.

## API Reference

### Vault

- `Vault.initialize()` - Initialize the SDK
- `Vault.reset()` - Reset and clean up
- `Vault.instance` - Get the singleton instance

### VaultAuth

- `signUp()` - Register new user
- `signInWithEmail()` - Email/password sign in
- `signInWithOAuth()` - OAuth sign in
- `sendMagicLink()` - Send magic link
- `verifyMagicLink()` - Verify magic link
- `sendPasswordResetEmail()` - Request password reset
- `resetPassword()` - Reset password with token
- `getMfaStatus()` - Get MFA status
- `enableMfa()` - Enable MFA
- `disableMfa()` - Disable MFA

### VaultSession

- `getCurrentUser()` - Get current user
- `isAuthenticated()` - Check authentication status
- `getToken()` - Get access token
- `signOut()` - Sign out current session
- `signOutAllDevices()` - Sign out everywhere
- `listSessions()` - List active sessions
- `revokeSession()` - Revoke specific session

### VaultOrganizations

- `list()` - List organizations
- `get()` - Get organization details
- `create()` - Create organization
- `update()` - Update organization
- `delete()` - Delete organization
- `listMembers()` - List members
- `inviteMember()` - Invite member
- `updateMember()` - Update member role
- `removeMember()` - Remove member

### VaultBiometric

- `isAvailable()` - Check if biometrics available
- `authenticate()` - Authenticate with biometrics
- `enableBiometricLogin()` - Enable biometric login
- `disableBiometricLogin()` - Disable biometric login
- `authenticateWithBiometrics()` - Sign in with biometrics

## Contributing

Contributions are welcome! Please read the [Contributing Guide](../../CONTRIBUTING.md) for details.

## License

This project is dual-licensed under MIT and Apache-2.0 licenses. See [LICENSE-MIT](../../LICENSE-MIT) and [LICENSE-APACHE](../../LICENSE-APACHE) for details.

## Support

- Documentation: https://docs.vault.dev/flutter-sdk
- Issues: https://github.com/yourorg/vault/issues
- Email: support@vault.dev
