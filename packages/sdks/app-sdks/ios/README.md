# Vault iOS SDK

A native Swift SDK for integrating Vault authentication and user management into iOS applications.

## Features

- 🔐 **Email/Password Authentication** - Traditional sign-in with email and password
- 🔑 **OAuth Providers** - Sign in with Apple, Google, Microsoft, GitHub, and more
- 👤 **Biometric Authentication** - Face ID / Touch ID with Secure Enclave
- 🏢 **Organization Support** - Multi-tenant B2B authentication
- 🔄 **Session Management** - Automatic token refresh and secure storage
- ⚡ **Swift Concurrency** - Full async/await support
- 📱 **SwiftUI & UIKit** - Works with both UI frameworks
- 🔗 **Combine Support** - Publishers for reactive UI updates
- 🔒 **Secure Storage** - Keychain-backed token storage

## Requirements

- iOS 15.0+
- macOS 12.0+
- tvOS 15.0+
- watchOS 8.0+
- Swift 5.7+

## Installation

### Swift Package Manager

Add the following to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/your-org/vault-sdk-ios.git", from: "1.0.0")
]
```

Or add via Xcode:
1. File → Add Package Dependencies...
2. Enter: `https://github.com/your-org/vault-sdk-ios.git`
3. Select the Vault package

## Quick Start

### 1. Configure the SDK

```swift
import Vault

// In your AppDelegate or @main app struct
Vault.configure(
    apiUrl: "https://api.vault.dev",
    tenantId: "your-tenant-id"
)
```

### 2. Sign In

```swift
let auth = Vault.shared.auth

do {
    let session = try await auth.signIn(
        email: "user@example.com",
        password: "password"
    )
    print("Signed in: \(session.currentUser?.email ?? "")")
} catch {
    print("Error: \(error.localizedDescription)")
}
```

### 3. Check Session State

```swift
if await Vault.shared.session.isAuthenticated {
    // User is signed in
}

// Or use Combine
Vault.shared.sessionPublisher
    .sink { state in
        switch state {
        case .authenticated(let user):
            print("Welcome, \(user.firstName ?? "")!")
        case .unauthenticated:
            print("Please sign in")
        case .refreshing:
            print("Refreshing session...")
        }
    }
```

## Usage Guide

### Authentication

```swift
// Email/Password
let session = try await Vault.shared.auth.signIn(
    email: "user@example.com",
    password: "password"
)

// Sign up
let newSession = try await Vault.shared.auth.signUp(
    email: "new@example.com",
    password: "securepassword",
    firstName: "John",
    lastName: "Doe"
)

// Sign out
try await Vault.shared.session.signOut()
```

### OAuth Authentication

```swift
// Standard OAuth (presents web view)
let oauth = Vault.shared.oauth
let session = try await oauth.signIn(with: .google)

// Sign in with Apple (native)
let appleSession = try await oauth.signInWithApple()

// Available providers
// .apple, .google, .microsoft, .github, .gitlab, 
// .discord, .slack, .twitter, .facebook, .linkedin
```

### Biometric Authentication

```swift
let biometric = Vault.shared.biometric

// Check availability
if biometric.isAvailable {
    print("Biometric type: \(biometric.biometricType.displayName)")
}

// Register biometric auth (one-time setup)
try await Vault.shared.auth.registerBiometric()

// Sign in with biometric
do {
    let success = try await biometric.authenticate(reason: "Sign in to Vault")
    if success {
        let session = try await Vault.shared.auth.signInWithBiometric()
    }
} catch {
    print("Biometric failed: \(error)")
}
```

### Session Management

```swift
let session = Vault.shared.session

// Get current user
if let user = await session.currentUser {
    print("Hello, \(user.fullName)")
}

// Get access token
if let token = await session.getToken() {
    // Use token for API calls
}

// Restore session on app launch
let restored = await session.restoreSession()
```

### Organization Management (B2B)

```swift
let orgs = Vault.shared.organizations

// List organizations
let list = try await orgs.list()

// Set active organization
if let firstOrg = list.first {
    try await orgs.setActive(firstOrg.id)
}

// Get active organization
if let active = await orgs.getActive() {
    print("Active org: \(active.name)")
}

// Listen for changes
orgs.activeOrganizationPublisher
    .sink { org in
        print("Active org changed: \(org?.name ?? "none")")
    }
```

### User Profile

```swift
// Get user service
let userService = VaultUserService(apiClient: Vault.shared.apiClient)

// Update profile
let updatedUser = try await userService.updateProfile(
    firstName: "Jane",
    lastName: "Smith"
)

// Upload profile image
let imageData: Data = // ... load image
let user = try await userService.uploadProfileImage(imageData)
```

## SwiftUI Integration

### Session Observation

```swift
import SwiftUI
import Vault

@main
struct MyApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
                .observeVaultSession()
        }
    }
}

struct ContentView: View {
    @EnvironmentObject var sessionObserver: SessionObserver
    
    var body: some View {
        Group {
            if sessionObserver.isAuthenticated {
                HomeView()
            } else {
                SignInView()
            }
        }
    }
}
```

### Profile Management

```swift
struct ProfileView: View {
    @StateObject private var profile = VaultProfile()
    
    var body: some View {
        VStack {
            if let user = profile.currentUser {
                Text(user.fullName)
                Text(user.email)
            }
        }
        .task {
            await profile.refresh()
        }
    }
}
```

### Biometric Button

```swift
struct BiometricSignInButton: View {
    let biometric = Vault.shared.biometric
    @State private var isLoading = false
    
    var body: some View {
        Button {
            signIn()
        } label: {
            HStack {
                Image(systemName: biometric.biometricType.iconName)
                Text("Sign in with \(biometric.biometricType.displayName)")
            }
        }
        .disabled(!biometric.isAvailable || isLoading)
    }
    
    private func signIn() {
        Task {
            isLoading = true
            defer { isLoading = false }
            
            do {
                _ = try await Vault.shared.auth.signInWithBiometric()
            } catch {
                // Handle error
            }
        }
    }
}
```

## Configuration Options

```swift
Vault.configure(
    apiUrl: "https://api.vault.dev",
    tenantId: "your-tenant-id",
    apiKey: "optional-api-key",      // For admin operations
    debugMode: true                   // Enable debug logging
)
```

## Error Handling

```swift
do {
    let session = try await Vault.shared.auth.signIn(email: email, password: password)
} catch VaultError.unauthorized {
    // Invalid credentials
} catch VaultError.networkError(let underlying) {
    // Network issue
} catch VaultError.validationFailed(let errors) {
    // Validation errors per field
    for (field, messages) in errors {
        print("\(field): \(messages.joined(separator: ", "))")
    }
} catch {
    // Other errors
}
```

## Security

The Vault SDK prioritizes security:

- **Keychain Storage**: All tokens stored in iOS Keychain with appropriate accessibility levels
- **Secure Enclave**: Biometric keys generated in hardware, private keys never leave the device
- **Certificate Pinning**: Built-in support for SSL pinning (configure via APIClient)
- **Automatic Token Refresh**: Handles token expiration transparently
- **Secure Memory**: Sensitive data cleared from memory when possible

## Advanced Usage

### Custom API Client

```swift
// Access the internal API client for custom requests
let client = Vault.shared.apiClient

// Make authenticated requests
let data = try await client.get(path: "/v1/custom/endpoint")
```

### Logging

```swift
// Enable debug logging
Vault.configure(
    apiUrl: "https://api.vault.dev",
    tenantId: "tenant-id",
    debugMode: true
)

// Custom log handler
VaultLogging.customHandler = { level, message in
    // Send to your analytics/logging service
    Analytics.log(message)
}
```

### Crypto Utilities

```swift
// Hashing
let hash = VaultCrypto.sha256("data")

// Random generation
let random = VaultCrypto.randomString(length: 32)
let bytes = try VaultCrypto.randomBytes(count: 32)

// HMAC
let signature = VaultCrypto.hmacSHA256("message", key: "secret")

// Password strength
let strength = VaultCrypto.passwordStrength("MyP@ssw0rd!")
```

## Testing

```swift
import XCTest
@testable import Vault

class AuthTests: XCTestCase {
    override func setUp() async throws {
        Vault.configure(
            apiUrl: "https://api.test.vault.dev",
            tenantId: "test-tenant"
        )
    }
    
    func testSignIn() async throws {
        // Your test implementation
    }
}
```

## Sample App

Check out the `Example/` directory for a complete sample iOS app demonstrating all SDK features.

## Documentation

For full API documentation, visit [docs.vault.dev/ios](https://docs.vault.dev/ios).

## Support

- 📧 Email: support@vault.dev
- 💬 Discord: [discord.gg/vault](https://discord.gg/vault)
- 🐛 Issues: [GitHub Issues](https://github.com/your-org/vault-sdk-ios/issues)

## License

Vault iOS SDK is available under the MIT license. See the LICENSE file for more info.

## Contributing

We welcome contributions! Please see CONTRIBUTING.md for guidelines.

---

Made with ❤️ by the Vault team
