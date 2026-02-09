/// Vault SDK for Flutter
/// 
/// A comprehensive authentication and user management SDK for Flutter applications.
/// Provides secure authentication, session management, organization support,
/// and biometric authentication.
/// 
/// ## Getting Started
/// 
/// ```dart
/// import 'package:vault_sdk/vault.dart';
/// 
/// void main() {
///   Vault.initialize(
///     apiUrl: 'https://api.vault.dev',
///     tenantId: 'my-tenant',
///   );
/// }
/// ```
/// 
/// ## Authentication
/// 
/// ```dart
/// final auth = VaultAuth();
/// 
/// // Email/password sign in
/// final result = await auth.signInWithEmail(
///   email: 'user@example.com',
///   password: 'password',
/// );
/// 
/// // OAuth
/// await auth.signInWithOAuth(provider: OAuthProvider.google);
/// ```
/// 
/// ## Session Management
/// 
/// ```dart
/// final session = VaultSession();
/// final user = await session.getCurrentUser();
/// final token = await session.getToken();
/// ```
/// 
/// ## Biometric Authentication
/// 
/// ```dart
/// final biometric = VaultBiometric();
/// if (await biometric.isAvailable()) {
///   final success = await biometric.authenticate(
///     reason: 'Verify your identity',
///   );
/// }
/// ```
library vault_sdk;

export 'src/vault.dart';
export 'src/auth.dart';
export 'src/user.dart';
export 'src/session.dart';
export 'src/organization.dart';
export 'src/api_client.dart';
export 'src/storage.dart';
export 'src/biometric.dart';
export 'src/exceptions.dart';
