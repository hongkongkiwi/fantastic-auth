# Changelog

All notable changes to the Vault Flutter SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2024-XX-XX

### Added
- Initial release of Vault Flutter SDK
- Email/password authentication (sign up, sign in, password reset)
- OAuth support for Google, Apple, GitHub, Microsoft, Discord, and Slack
- Magic link authentication for passwordless sign-in
- Biometric authentication (Face ID, Touch ID, Fingerprint)
- Secure storage using iOS Keychain and Android Keystore
- Session management with automatic token refresh
- Organization/team management with RBAC
- Multi-factor authentication (TOTP, Email, SMS, WebAuthn, Backup Codes)
- SSO support (SAML 2.0, OIDC)
- Comprehensive error handling with specific exception types
- Cross-platform support for iOS and Android

### Security
- Implements secure token storage
- Automatic token refresh before expiration
- Support for encrypted shared preferences on Android
- Keychain accessibility options for iOS
- Biometric authentication with device credential fallback
