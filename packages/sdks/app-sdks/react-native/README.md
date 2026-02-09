# @fantasticauth/react-native

React Native SDK for Vault - Secure mobile authentication with biometrics.

## Features

- 🔐 **Secure Storage** - Uses iOS Keychain and Android Keystore for token storage
- 👆 **Biometric Authentication** - Face ID, Touch ID, and Fingerprint support
- 🔗 **OAuth Deep Linking** - Native in-app browser OAuth flows
- 📱 **Expo Compatible** - Works with both Expo and bare React Native workflows
- 🔄 **Session Management** - Automatic token refresh and session handling
- 🏢 **Organizations** - Multi-tenant organization support
- 🔑 **WebAuthn/Passkeys** - Platform authenticator support

## Installation

```bash
npm install @fantasticauth/react-native
# or
yarn add @fantasticauth/react-native
```

### Optional Dependencies

For full functionality, install the optional peer dependencies:

```bash
# Secure storage (highly recommended)
npm install react-native-keychain

# In-app browser for OAuth
npm install react-native-inappbrowser-reborn

# Async storage for non-sensitive data
npm install @react-native-async-storage/async-storage

# Biometric authentication
npm install react-native-biometrics

# For Expo users:
npx expo install @expo/local-authentication expo-secure-store
```

## Quick Start

### 1. Configure Deep Links

Add URL scheme to your app configuration:

**iOS (`ios/YourApp/Info.plist`):**
```xml
<key>CFBundleURLTypes</key>
<array>
  <dict>
    <key>CFBundleURLName</key>
    <string>com.yourcompany.vault</string>
    <key>CFBundleURLSchemes</key>
    <array>
      <string>yourapp</string>
    </array>
  </dict>
</array>
```

**Android (`android/app/src/main/AndroidManifest.xml`):**
```xml
<activity android:name="com.facebook.react.devsupport.DevSettingsActivity" />
<intent-filter>
  <action android:name="android.intent.action.VIEW" />
  <category android:name="android.intent.category.DEFAULT" />
  <category android:name="android.intent.category.BROWSABLE" />
  <data android:scheme="yourapp" />
</intent-filter>
```

**Expo (`app.json`):**
```json
{
  "expo": {
    "scheme": "yourapp"
  }
}
```

### 2. Wrap Your App with VaultProvider

```tsx
import { VaultProvider } from '@fantasticauth/react-native';

export default function App() {
  return (
    <VaultProvider
      config={{
        apiUrl: 'https://api.vault.dev',
        tenantId: 'my-tenant',
        enableBiometricUnlock: true,
        oauthRedirectScheme: 'yourapp',
      }}
    >
      <NavigationContainer>
        <RootNavigator />
      </NavigationContainer>
    </VaultProvider>
  );
}
```

### 3. Use Authentication Hooks

```tsx
import { useAuth, useUser, SignIn } from '@fantasticauth/react-native';

function HomeScreen() {
  const { isSignedIn, user, signOut, isLocked, unlockWithBiometrics } = useAuth();

  if (isLocked) {
    return (
      <View>
        <Text>App is locked</Text>
        <Button title="Unlock" onPress={unlockWithBiometrics} />
      </View>
    );
  }

  if (!isSignedIn) {
    return <SignIn oauthProviders={['google', 'apple']} />;
  }

  return (
    <View>
      <Text>Welcome, {user?.email}!</Text>
      <Button title="Sign Out" onPress={signOut} />
    </View>
  );
}
```

## Usage

### Secure Storage

```typescript
import { SecureStorage } from '@fantasticauth/react-native';

// Store session token securely
await SecureStorage.setItem('fantasticauth_session_token', token);

// Retrieve session token
const token = await SecureStorage.getItem('fantasticauth_session_token');

// Remove item
await SecureStorage.removeItem('fantasticauth_session_token');
```

### Biometric Authentication

```tsx
import { useBiometricAuth } from '@fantasticauth/react-native';

function SecureAction() {
  const { isAvailable, biometricType, authenticate } = useBiometricAuth();

  const handleSecureAction = async () => {
    const result = await authenticate('Confirm secure action');
    if (result.success) {
      // Proceed with secure action
    }
  };

  return (
    <View>
      {isAvailable && (
        <Button 
          title={`Authenticate with ${biometricType}`}
          onPress={handleSecureAction}
        />
      )}
    </View>
  );
}
```

### OAuth Sign In

```tsx
import { useSignIn, OAuthButton } from '@fantasticauth/react-native';

function SignInScreen() {
  const { signInWithOAuth, isLoading } = useSignIn();

  return (
    <View>
      <OAuthButton
        provider="google"
        onSuccess={() => navigation.navigate('Home')}
        onError={(error) => console.error(error)}
      />
      
      <OAuthButton
        provider="apple"
        text="Sign in with Apple"
        onSuccess={() => navigation.navigate('Home')}
      />
    </View>
  );
}
```

### Organizations

```tsx
import { useOrganization, OrganizationSwitcher } from '@fantasticauth/react-native';

function OrganizationScreen() {
  const { 
    organizations, 
    organization, 
    setActive,
    create,
    isLoading 
  } = useOrganization();

  return (
    <View>
      <OrganizationSwitcher 
        onSwitch={(org) => console.log('Switched to:', org?.name)}
      />
      
      <Text>Current: {organization?.name || 'Personal'}</Text>
      
      {organizations.map(org => (
        <Button
          key={org.id}
          title={org.name}
          onPress={() => setActive(org.id)}
        />
      ))}
    </View>
  );
}
```

### Session Management

```tsx
import { useSession, useSessions } from '@fantasticauth/react-native';

function SessionManager() {
  const { session, getToken, refresh } = useSession();
  const { sessions, revokeSession, revokeAllOtherSessions } = useSessions();

  const makeApiCall = async () => {
    const token = await getToken();
    // Use token for external API calls
  };

  return (
    <View>
      <Text>Active Sessions: {sessions.length}</Text>
      
      {sessions.map(s => (
        <SessionItem
          key={s.id}
          session={s}
          onRevoke={() => revokeSession(s.id)}
        />
      ))}
      
      <Button 
        title="Sign out all other devices"
        onPress={revokeAllOtherSessions}
      />
    </View>
  );
}
```

## Configuration

### VaultProvider Props

| Prop | Type | Description |
|------|------|-------------|
| `config` | `VaultConfig` | Required. API URL, tenant ID, and other options |
| `initialUser` | `User` | Optional. Initial user data for SSR |
| `onAuthStateChange` | `(state) => void` | Optional. Callback when auth state changes |
| `loadingComponent` | `ReactNode` | Optional. Custom loading component |
| `biometricLockComponent` | `ReactNode` | Optional. Custom biometric lock screen |

### VaultConfig Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `apiUrl` | `string` | required | Your Vault API URL |
| `tenantId` | `string` | required | Your tenant ID |
| `enableBiometricUnlock` | `boolean` | `false` | Enable biometric app lock |
| `biometricPrompt` | `string` | `'Verify your identity'` | Biometric prompt message |
| `oauthRedirectScheme` | `string` | `'vault'` | Custom OAuth redirect scheme |
| `enableSecureStorage` | `boolean` | `true` | Use Keychain/Keystore |
| `enableOfflineSupport` | `boolean` | `true` | Cache data for offline use |
| `sessionRefreshInterval` | `number` | `300000` | Token refresh interval (ms) |

## API Reference

### Hooks

- `useAuth()` - Authentication state and methods
- `useUser()` - Current user data
- `useUserManager()` - User management operations
- `useSession()` - Session data and token management
- `useSessions()` - Multi-device session management
- `useSignIn()` - Sign-in with loading/error states
- `useSignUp()` - Sign-up with loading/error states
- `useOrganization()` - Organization management
- `useBiometricAuth()` - Biometric authentication
- `useWebAuthn()` - WebAuthn/Passkey operations
- `useOAuthDeepLink()` - OAuth callback handling

### Components

- `<SignIn />` - Pre-built sign-in screen
- `<SignUp />` - Pre-built sign-up screen
- `<UserButton />` - User avatar with dropdown menu
- `<UserProfile />` - Profile management screen
- `<OrganizationSwitcher />` - Organization selection
- `<OAuthButton />` - OAuth provider button

## Platform Considerations

### iOS

- Requires `NSFaceIDUsageDescription` in Info.plist for Face ID
- Keychain items persist across app reinstalls

```xml
<key>NSFaceIDUsageDescription</key>
<string>Authenticate to access your account</string>
```

### Android

- Requires `USE_BIOMETRIC` permission for fingerprint
- Keystore is hardware-backed on most devices

```xml
<uses-permission android:name="android.permission.USE_BIOMETRIC" />
```

### Expo

- Use `@expo/local-authentication` for biometrics
- Use `expo-secure-store` for secure storage
- No ejecting required for basic functionality

## Security

- Session tokens are stored in iOS Keychain / Android Keystore
- Biometric authentication uses platform hardware security
- OAuth flows use in-app browsers to prevent phishing
- Automatic token refresh prevents session expiration
- App lock on background with biometric re-authentication

## License

MIT
