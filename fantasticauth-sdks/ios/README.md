# VaultAuth iOS SDK

Native iOS SDK for Vault authentication with support for secure token storage, biometric authentication, MFA, push notifications, and pre-built UI components.

## Features

- 🔐 **Secure Authentication** - Email/password, OAuth (Google, Apple, Microsoft, GitHub, Facebook)
- 🔑 **Keychain Token Storage** - Securely store authentication tokens using iOS Keychain
- 👤 **Biometric Login** - Face ID / Touch ID authentication support
- 📱 **Push Notifications** - Handle MFA push notifications
- 🏢 **Organizations** - Multi-tenant organization support
- 🎨 **Pre-built UI** - Ready-to-use login and signup view controllers
- ⚡ **SwiftUI Support** - Native SwiftUI views and property wrappers
- 🔄 **Session Management** - Automatic token refresh and session persistence

## Requirements

- iOS 13.0+
- Swift 5.7+
- Xcode 14.0+

## Installation

### Swift Package Manager

Add the following to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/vault/ios-sdk.git", from: "1.0.0")
]
```

Or in Xcode: **File → Add Packages → `https://github.com/vault/ios-sdk.git`**

### CocoaPods

Add to your `Podfile`:

```ruby
pod 'VaultAuth', '~> 1.0'
```

Then run:

```bash
pod install
```

## Quick Start

### 1. Configure the SDK

In your `AppDelegate` or `@main` App struct:

```swift
import VaultAuth

@main
struct MyApp: App {
    init() {
        VaultAuth.shared.configure(
            apiKey: "your_api_key",
            baseURL: "https://vault.example.com",
            tenantId: "your_tenant_id" // Optional
        )
    }
    
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
```

### 2. Handle Push Notifications

```swift
import VaultAuth

class AppDelegate: NSObject, UIApplicationDelegate {
    func application(
        _ application: UIApplication,
        didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data
    ) {
        VaultAuth.shared.registerForPushNotifications(deviceToken: deviceToken)
    }
    
    func application(
        _ application: UIApplication,
        didReceiveRemoteNotification userInfo: [AnyHashable: Any]
    ) {
        VaultAuth.shared.handlePushNotification(userInfo)
    }
}
```

## Usage

### Email/Password Authentication

```swift
// Login
Task {
    do {
        let user = try await VaultAuth.shared.login(
            email: "user@example.com",
            password: "password123"
        )
        print("Logged in as: \(user.email)")
    } catch {
        print("Login failed: \(error)")
    }
}

// Signup
Task {
    do {
        let user = try await VaultAuth.shared.signup(
            email: "user@example.com",
            password: "password123",
            name: "John Doe"
        )
        print("Created account: \(user.email)")
    } catch {
        print("Signup failed: \(error)")
    }
}

// Logout
Task {
    try await VaultAuth.shared.logout()
}
```

### Biometric Authentication

```swift
// Check if biometric is available
if BiometricAuth.shared.canUseBiometricLogin {
    // Enable biometric login (requires password)
    Task {
        do {
            let success = try await BiometricAuth.shared.enableBiometricLogin(
                email: "user@example.com",
                password: "password123"
            )
            print("Biometric login enabled: \(success)")
        } catch {
            print("Failed to enable: \(error)")
        }
    }
    
    // Login with biometric
    Task {
        do {
            let user = try await VaultAuth.shared.loginWithBiometric()
            print("Logged in with biometrics")
        } catch {
            print("Biometric login failed: \(error)")
        }
    }
}

// Disable biometric login
try? BiometricAuth.shared.disableBiometricLogin()
```

### OAuth Authentication

```swift
Task {
    do {
        let user = try await VaultAuth.shared.loginWithOAuth(
            provider: .google,
            from: viewController
        )
        print("Logged in via Google: \(user.email)")
    } catch VaultAuthError.oauthCancelled {
        print("User cancelled OAuth")
    } catch {
        print("OAuth failed: \(error)")
    }
}
```

### Multi-Factor Authentication (MFA)

```swift
// Enable MFA
Task {
    do {
        let response = try await VaultAuth.shared.enableMFA(method: .totp)
        // Show QR code from response.qrCodeUri
        // Save backup codes from response.backupCodes
    } catch {
        print("Failed to enable MFA: \(error)")
    }
}

// Verify MFA code
Task {
    do {
        let user = try await VaultAuth.shared.verifyMFA(code: "123456")
        print("MFA verified, logged in as: \(user.email)")
    } catch {
        print("Invalid MFA code: \(error)")
    }
}
```

### Organizations

```swift
// Get user's organizations
Task {
    do {
        let organizations = try await VaultAuth.shared.getOrganizations()
        for org in organizations {
            print("\(org.name) - \(org.role.displayName)")
        }
    } catch {
        print("Failed to get organizations: \(error)")
    }
}

// Switch organization
Task {
    do {
        let org = try await VaultAuth.shared.switchOrganization("org_123")
        print("Switched to: \(org.name)")
    } catch {
        print("Failed to switch: \(error)")
    }
}
```

### Push Notifications for MFA

```swift
// Handle MFA push notification approval
func handleMFAPush(request: MFARequest) {
    Task {
        do {
            try await VaultAuth.shared.pushNotificationHandler?.approveMFARequest(
                requestId: request.requestId
            )
        } catch {
            print("Failed to approve: \(error)")
        }
    }
}

// Set up push notification handlers
PushNotificationManager.shared.onMFARequest = { request in
    // Show UI to approve/deny
    showMFAPrompt(request: request)
}
```

## UI Components

### UIKit View Controllers

```swift
// Login View Controller
let loginVC = VaultLoginViewController(theme: .default)
loginVC.onLoginSuccess = { user in
    print("User logged in: \(user.email)")
}
loginVC.onLoginError = { error in
    print("Login error: \(error)")
}
loginVC.onSignupTap = {
    // Navigate to signup
}
present(loginVC, animated: true)

// Signup View Controller
let signupVC = VaultSignupViewController(theme: .default)
signupVC.onSignupSuccess = { user in
    print("User signed up: \(user.email)")
}
navigationController?.pushViewController(signupVC, animated: true)

// Profile View Controller
let profileVC = VaultProfileViewController(theme: .default)
profileVC.onLogout = {
    // Handle logout
}
navigationController?.pushViewController(profileVC, animated: true)
```

### SwiftUI Views

```swift
import SwiftUI
import VaultAuth

struct ContentView: View {
    @VaultAuthState var authState
    
    var body: some View {
        Group {
            if let user = authState.currentUser {
                MainView(user: user)
            } else {
                VaultLoginView { user in
                    print("Logged in: \(user.email)")
                } onError: { error in
                    print("Error: \(error)")
                }
            }
        }
    }
}

// Alternative using view model
struct AuthView: View {
    @StateObject private var viewModel = VaultAuthViewModel()
    
    var body: some View {
        NavigationView {
            if viewModel.isAuthenticated, let user = viewModel.currentUser {
                ProfileView(user: user)
                    .toolbar {
                        Button("Logout") {
                            Task { await viewModel.logout() }
                        }
                    }
            } else {
                VaultLoginView(onSuccess: { _ in })
            }
        }
    }
}
```

### Custom Theming

```swift
// Create a custom theme
let customTheme = VaultTheme(
    primaryColor: .purple,
    backgroundColor: .black,
    surfaceColor: .darkGray,
    textColor: .white,
    cornerRadius: 16,
    padding: 32
)

// Use with view controllers
let loginVC = VaultLoginViewController(theme: customTheme)

// Use with SwiftUI
VaultLoginView(primaryColor: .purple, onSuccess: { _ in })
```

## Secure Token Storage

The SDK uses iOS Keychain by default for secure token storage. You can also provide your own storage implementation:

```swift
// Custom token storage
class MyTokenStorage: TokenStorage {
    func saveToken(_ token: String, forKey key: String) throws {
        // Your implementation
    }
    
    func getToken(forKey key: String) -> String? {
        // Your implementation
    }
    
    func deleteToken(forKey key: String) throws {
        // Your implementation
    }
    
    func deleteAllTokens() throws {
        // Your implementation
    }
}

// Configure with custom storage
VaultAuth.shared.configure(
    apiKey: "your_api_key",
    baseURL: "https://vault.example.com",
    tokenStorage: MyTokenStorage()
)
```

## Error Handling

```swift
do {
    let user = try await VaultAuth.shared.login(email: email, password: password)
} catch VaultAuthError.invalidCredentials {
    // Show "Invalid email or password"
} catch VaultAuthError.mfaRequired {
    // Show MFA code input
} catch VaultAuthError.biometricNotAvailable {
    // Device doesn't support biometrics
} catch VaultAuthError.networkError(let underlyingError) {
    // Show network error
} catch {
    // Handle other errors
}
```

## Advanced Configuration

### Custom URLSession

```swift
let configuration = URLSessionConfiguration.default
configuration.timeoutIntervalForRequest = 30
configuration.timeoutIntervalForResource = 300

let session = URLSession(configuration: configuration)

let client = VaultClient(
    baseURL: URL(string: "https://vault.example.com")!,
    apiKey: "your_api_key",
    urlSession: session
)
```

### Keychain Access Groups

For sharing authentication state between app and extensions:

```swift
let keychainStorage = KeychainStorage(
    service: "com.yourcompany.vault",
    accessGroup: "group.com.yourcompany.shared",
    accessibility: kSecAttrAccessibleAfterFirstUnlock
)

VaultAuth.shared.configure(
    apiKey: "your_api_key",
    baseURL: "https://vault.example.com",
    tokenStorage: keychainStorage
)
```

## License

This SDK is available under the MIT license. See LICENSE for details.

## Support

For support, email support@vault.example.com or visit https://docs.vault.example.com
