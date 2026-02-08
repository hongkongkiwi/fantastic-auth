# Changelog

All notable changes to the Vault iOS SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-XX-XX

### Added
- Initial release of Vault iOS SDK
- Email/password authentication (sign in, sign up, password reset)
- OAuth authentication with Apple, Google, Microsoft, GitHub, GitLab, Discord, Slack, Twitter, Facebook, and LinkedIn
- Native Sign in with Apple support
- Biometric authentication with Face ID and Touch ID
- Secure Enclave key generation and storage
- Session management with automatic token refresh
- Secure keychain-backed token storage
- Organization management for B2B multi-tenancy
- User profile management
- SwiftUI integration with environment objects and view modifiers
- Combine publishers for reactive UI updates
- Comprehensive error handling with VaultError types
- Cryptographic utilities (SHA-256, HMAC, random generation)
- Password strength checking
- Full async/await support
- iOS 15+, macOS 12+, tvOS 15+, watchOS 8+ support

### Security
- Secure Enclave integration for biometric-protected keys
- Keychain storage for authentication tokens
- Hardware-backed key generation
- Automatic secure memory clearing

## [Unreleased]

### Planned
- Certificate pinning support
- Offline mode with request queuing
- Push notification support
- WebAuthn/Passkey support
- Session analytics and monitoring
- Widget support for iOS 17+

---

## Version History Notes

### Version Numbering
- **Major**: Breaking API changes
- **Minor**: New features, backwards compatible
- **Patch**: Bug fixes, backwards compatible

### Deprecation Policy
- Deprecated APIs will be marked with `@available` attributes
- Deprecated APIs will be supported for at least 2 minor versions
- Migration guides will be provided for breaking changes
