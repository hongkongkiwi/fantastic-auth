import 'dart:async';

import 'package:url_launcher/url_launcher.dart';

import 'api_client.dart';
import 'exceptions.dart';
import 'session.dart';
import 'storage.dart';
import 'user.dart';

/// Authentication methods for Vault SDK
class VaultAuth {
  static VaultAuth? _instance;

  /// API client
  final VaultApiClient _apiClient;
  
  /// Session instance
  final VaultSession _session;
  
  /// Storage instance
  final VaultStorage _storage;

  VaultAuth._({
    VaultApiClient? apiClient,
    VaultSession? session,
    VaultStorage? storage,
  })  : _apiClient = apiClient ?? VaultApiClient.instance,
        _session = session ?? VaultSession.instance,
        _storage = storage ?? VaultStorage.instance;

  /// Get or create the singleton instance
  factory VaultAuth({
    VaultApiClient? apiClient,
    VaultSession? session,
    VaultStorage? storage,
  }) {
    _instance ??= VaultAuth._(
      apiClient: apiClient,
      session: session,
      storage: storage,
    );
    return _instance!;
  }

  /// Get the singleton instance
  static VaultAuth get instance {
    if (_instance == null) {
      throw const VaultAuthException(
        'VaultAuth not initialized. Call Vault.initialize() first.',
      );
    }
    return _instance!;
  }

  // ===== Email/Password Authentication =====

  /// Register a new user with email and password
  /// 
  /// Returns the authenticated user session
  Future<AuthResult> signUp({
    required String email,
    required String password,
    String? name,
  }) async {
    final body = <String, dynamic>{
      'email': email,
      'password': password,
      if (name != null) 'name': name,
    };

    final response = await _apiClient.post(
      '/auth/register',
      body: body,
      authenticated: false,
    );

    return _handleAuthResponse(response as Map<String, dynamic>);
  }

  /// Sign in with email and password
  /// 
  /// Returns the authenticated user session
  Future<AuthResult> signInWithEmail({
    required String email,
    required String password,
    String? mfaCode,
  }) async {
    final body = <String, dynamic>{
      'email': email,
      'password': password,
      if (mfaCode != null) 'mfaCode': mfaCode,
    };

    final response = await _apiClient.post(
      '/auth/login',
      body: body,
      authenticated: false,
    );

    return _handleAuthResponse(response as Map<String, dynamic>);
  }

  // ===== Magic Link Authentication =====

  /// Send a magic link to the user's email
  /// 
  /// This initiates passwordless authentication
  Future<void> sendMagicLink(String email) async {
    await _apiClient.post(
      '/auth/magic-link',
      body: {'email': email},
      authenticated: false,
    );
  }

  /// Verify a magic link token
  /// 
  /// Call this with the token from the magic link URL
  Future<AuthResult> verifyMagicLink(String token) async {
    final response = await _apiClient.post(
      '/auth/magic-link/verify',
      body: {'token': token},
      authenticated: false,
    );

    return _handleAuthResponse(response as Map<String, dynamic>);
  }

  // ===== OAuth Authentication =====

  /// Initiate OAuth sign-in
  /// 
  /// Opens the OAuth provider's login page
  Future<void> signInWithOAuth({
    required OAuthProvider provider,
    String? redirectUri,
  }) async {
    final body = <String, dynamic>{
      if (redirectUri != null) 'redirectUri': redirectUri,
    };

    final response = await _apiClient.post(
      '/auth/oauth/${provider.name}',
      body: body.isNotEmpty ? body : null,
      authenticated: false,
    );

    final url = response?['url'] as String?;
    if (url == null) {
      throw VaultOAuthException(
        'No OAuth URL returned',
        provider: provider.name,
      );
    }

    final uri = Uri.parse(url);
    final launched = await launchUrl(
      uri,
      mode: LaunchMode.externalApplication,
    );

    if (!launched) {
      throw VaultOAuthException(
        'Could not launch OAuth URL',
        provider: provider.name,
      );
    }
  }

  /// Handle OAuth callback
  /// 
  /// Call this when the app receives the OAuth callback
  Future<AuthResult> handleOAuthCallback({
    required OAuthProvider provider,
    required String code,
    required String state,
  }) async {
    final queryParams = <String, String>{
      'code': code,
      'state': state,
    };

    // The API client doesn't have a get with query params method
    // We'll construct the URL manually
    final response = await _apiClient.get(
      '/auth/oauth/${provider.name}/callback',
      queryParams: queryParams,
      authenticated: false,
    );

    return _handleAuthResponse(response as Map<String, dynamic>);
  }

  /// Check if URL is a Vault OAuth callback
  bool isOAuthCallback(Uri uri, {OAuthProvider? provider}) {
    final path = uri.path;
    if (provider != null) {
      return path.contains('/auth/oauth/${provider.name}/callback');
    }
    return path.contains('/auth/oauth/') && path.contains('/callback');
  }

  /// Extract OAuth result from callback URL
  OAuthCallbackResult? extractOAuthResult(Uri uri) {
    final code = uri.queryParameters['code'];
    final state = uri.queryParameters['state'];
    final error = uri.queryParameters['error'];
    final errorDescription = uri.queryParameters['error_description'];

    if (error != null) {
      return OAuthCallbackResult.error(
        error: error,
        description: errorDescription,
      );
    }

    if (code != null && state != null) {
      // Extract provider from path
      final pathSegments = uri.pathSegments;
      String? provider;
      for (var i = 0; i < pathSegments.length; i++) {
        if (pathSegments[i] == 'oauth' && i + 1 < pathSegments.length) {
          provider = pathSegments[i + 1];
          break;
        }
      }

      return OAuthCallbackResult.success(
        code: code,
        state: state,
        provider: provider,
      );
    }

    return null;
  }

  // ===== Password Reset =====

  /// Request a password reset email
  Future<void> sendPasswordResetEmail(String email) async {
    await _apiClient.post(
      '/auth/forgot-password',
      body: {'email': email},
      authenticated: false,
    );
  }

  /// Reset password with token
  Future<void> resetPassword({
    required String token,
    required String newPassword,
  }) async {
    await _apiClient.post(
      '/auth/reset-password',
      body: {
        'token': token,
        'newPassword': newPassword,
      },
      authenticated: false,
    );
  }

  // ===== Email Verification =====

  /// Verify email address with token
  Future<VaultUser> verifyEmail(String token) async {
    final response = await _apiClient.post(
      '/auth/verify-email',
      body: {'token': token},
      authenticated: false,
    );

    final user = VaultUser.fromJson(response as Map<String, dynamic>);
    await _session.updateCurrentUser(user);
    return user;
  }

  /// Resend email verification
  Future<void> resendEmailVerification() async {
    // This endpoint would need to be added to the API
    // For now, we'll throw an exception
    throw const VaultException(
      'Resend email verification not implemented',
      code: 'NOT_IMPLEMENTED',
    );
  }

  // ===== SSO Authentication =====

  /// Initiate SSO login
  /// 
  /// Either [domain] or [connectionId] must be provided
  Future<void> signInWithSso({
    String? domain,
    String? connectionId,
  }) async {
    if (domain == null && connectionId == null) {
      throw const VaultAuthException(
        'Either domain or connectionId must be provided',
        code: 'INVALID_SSO_REQUEST',
      );
    }

    final queryParams = <String, String>{
      if (domain != null) 'domain': domain,
      if (connectionId != null) 'connection_id': connectionId,
    };

    final response = await _apiClient.get(
      '/auth/sso/redirect',
      queryParams: queryParams,
      authenticated: false,
    );

    final url = response?['url'] as String?;
    if (url == null) {
      throw const VaultAuthException(
        'No SSO redirect URL returned',
        code: 'SSO_ERROR',
      );
    }

    final uri = Uri.parse(url);
    final launched = await launchUrl(
      uri,
      mode: LaunchMode.externalApplication,
    );

    if (!launched) {
      throw const VaultAuthException(
        'Could not launch SSO URL',
        code: 'SSO_ERROR',
      );
    }
  }

  /// Handle SSO callback
  Future<AuthResult> handleSsoCallback({
    required String connectionId,
    required Map<String, dynamic> payload,
  }) async {
    final response = await _apiClient.post(
      '/auth/sso/callback',
      body: {
        'connectionId': connectionId,
        'payload': payload,
      },
      authenticated: false,
    );

    return _handleAuthResponse(response as Map<String, dynamic>);
  }

  // ===== MFA Methods =====

  /// Get MFA status for current user
  Future<MfaStatus> getMfaStatus() async {
    final response = await _apiClient.get(
      '/users/me/mfa',
      authenticated: true,
    );

    return MfaStatus.fromJson(response as Map<String, dynamic>);
  }

  /// Enable MFA
  /// 
  /// For TOTP, returns setup information including secret and QR code URI.
  /// For other methods, initiates the setup process.
  Future<MfaSetupResult> enableMfa(MfaMethod method, {String? code}) async {
    final body = <String, dynamic>{
      'method': method.name,
      if (code != null) 'code': code,
    };

    final response = await _apiClient.post(
      '/users/me/mfa',
      body: body,
      authenticated: true,
    );

    // TOTP setup returns additional data
    if (response is Map<String, dynamic> && response.containsKey('secret')) {
      return MfaSetupResult.totp(
        secret: response['secret'] as String,
        qrCodeUri: response['qrCodeUri'] as String,
        backupCodes: (response['backupCodes'] as List<dynamic>).cast<String>(),
      );
    }

    return const MfaSetupResult.success();
  }

  /// Disable MFA
  Future<void> disableMfa(String code) async {
    await _apiClient.delete(
      '/users/me/mfa',
      body: {'code': code},
      authenticated: true,
    );
  }

  /// Verify MFA code during sign-in
  Future<AuthResult> verifyMfaCode(String code) async {
    // This would typically be done as part of the sign-in flow
    // The MFA code is passed in the initial sign-in request
    throw const VaultException(
      'Use signInWithEmail with mfaCode parameter',
      code: 'USE_SIGN_IN_METHOD',
    );
  }

  /// Generate MFA backup codes
  Future<List<String>> generateBackupCodes() async {
    final response = await _apiClient.post(
      '/users/me/mfa/backup-codes',
      authenticated: true,
    );

    final codes = response?['codes'] as List<dynamic>?;
    return codes?.cast<String>() ?? [];
  }

  /// Verify a backup code
  Future<void> verifyBackupCode(String code) async {
    await _apiClient.post(
      '/users/me/mfa/backup-codes/verify',
      body: {'code': code},
      authenticated: true,
    );
  }

  // ===== Private Methods =====

  /// Handle authentication response
  AuthResult _handleAuthResponse(Map<String, dynamic> response) {
    // Check if MFA is required
    final mfaRequired = response['mfaRequired'] as bool? ?? false;
    if (mfaRequired) {
      return AuthResult.mfaRequired(
        availableMethods: (response['availableMethods'] as List<dynamic>?)
            ?.cast<String>() ??
            [],
      );
    }

    // Extract tokens and user
    final accessToken = response['accessToken'] as String?;
    final refreshToken = response['refreshToken'] as String?;
    final userData = response['user'] as Map<String, dynamic>?;

    if (accessToken == null || refreshToken == null || userData == null) {
      throw const VaultAuthException(
        'Invalid authentication response',
        code: 'INVALID_RESPONSE',
      );
    }

    final user = VaultUser.fromJson(userData);

    // Calculate token expiration
    final expiresIn = response['expiresIn'] as int? ?? 900; // Default 15 min
    final expiration = DateTime.now().add(Duration(seconds: expiresIn));

    // Store session
    _session.setSession(
      accessToken: accessToken,
      refreshToken: refreshToken,
      user: user,
      tokenExpiration: expiration,
    );

    return AuthResult.success(user: user);
  }
}

/// Authentication result
class AuthResult {
  /// Whether authentication was successful
  final bool success;
  
  /// Whether MFA is required
  final bool mfaRequired;
  
  /// Available MFA methods (if MFA is required)
  final List<String> availableMethods;
  
  /// Authenticated user (if successful)
  final VaultUser? user;
  
  /// Error message (if failed)
  final String? error;

  const AuthResult._({
    required this.success,
    this.mfaRequired = false,
    this.availableMethods = const [],
    this.user,
    this.error,
  });

  /// Successful authentication
  const AuthResult.success({required this.user})
      : success = true,
        mfaRequired = false,
        availableMethods = const [],
        error = null;

  /// MFA required
  const AuthResult.mfaRequired({this.availableMethods = const []})
      : success = false,
        mfaRequired = true,
        user = null,
        error = null;

  /// Authentication failed
  const AuthResult.failure({required this.error})
      : success = false,
        mfaRequired = false,
        availableMethods = const [],
        user = null;

  @override
  String toString() {
    if (success) return 'AuthResult.success(user: ${user?.email})';
    if (mfaRequired) return 'AuthResult.mfaRequired(methods: $availableMethods)';
    return 'AuthResult.failure(error: $error)';
  }
}

/// OAuth callback result
class OAuthCallbackResult {
  /// Whether the OAuth flow was successful
  final bool success;
  
  /// Authorization code (if successful)
  final String? code;
  
  /// State parameter (if successful)
  final String? state;
  
  /// OAuth provider
  final String? provider;
  
  /// Error code (if failed)
  final String? error;
  
  /// Error description (if failed)
  final String? errorDescription;

  const OAuthCallbackResult._({
    required this.success,
    this.code,
    this.state,
    this.provider,
    this.error,
    this.errorDescription,
  });

  /// Successful OAuth callback
  const OAuthCallbackResult.success({
    required this.code,
    required this.state,
    this.provider,
  })  : success = true,
        error = null,
        errorDescription = null;

  /// Failed OAuth callback
  const OAuthCallbackResult.error({
    required this.error,
    this.errorDescription,
  })  : success = false,
        code = null,
        state = null,
        provider = null;

  @override
  String toString() {
    if (success) {
      return 'OAuthCallbackResult.success(provider: $provider)';
    }
    return 'OAuthCallbackResult.error(error: $error)';
  }
}

/// MFA status
class MfaStatus {
  /// Whether MFA is enabled
  final bool enabled;
  
  /// Enabled MFA methods
  final List<MfaMethodInfo> methods;

  const MfaStatus({
    required this.enabled,
    required this.methods,
  });

  /// Create from JSON
  factory MfaStatus.fromJson(Map<String, dynamic> json) {
    return MfaStatus(
      enabled: json['enabled'] as bool? ?? false,
      methods: (json['methods'] as List<dynamic>?)
          ?.map((e) => MfaMethodInfo.fromJson(e as Map<String, dynamic>))
          .toList() ??
          [],
    );
  }

  /// Check if a specific method is enabled
  bool isMethodEnabled(MfaMethod method) {
    return methods.any((m) => m.method == method.name && m.enabled);
  }
}

/// MFA method information
class MfaMethodInfo {
  /// Method type
  final String method;
  
  /// Whether the method is enabled
  final bool enabled;
  
  /// When the method was created
  final DateTime? createdAt;
  
  /// When the method was last used
  final DateTime? lastUsedAt;

  MfaMethodInfo({
    required this.method,
    required this.enabled,
    this.createdAt,
    this.lastUsedAt,
  });

  /// Create from JSON
  factory MfaMethodInfo.fromJson(Map<String, dynamic> json) {
    return MfaMethodInfo(
      method: json['method'] as String,
      enabled: json['enabled'] as bool? ?? false,
      createdAt: json['createdAt'] != null
          ? DateTime.parse(json['createdAt'] as String)
          : null,
      lastUsedAt: json['lastUsedAt'] != null
          ? DateTime.parse(json['lastUsedAt'] as String)
          : null,
    );
  }
}

/// MFA setup result
class MfaSetupResult {
  /// Whether setup was successful
  final bool success;
  
  /// For TOTP: the secret key
  final String? secret;
  
  /// For TOTP: the QR code URI
  final String? qrCodeUri;
  
  /// Backup codes (if generated)
  final List<String>? backupCodes;

  const MfaSetupResult._({
    required this.success,
    this.secret,
    this.qrCodeUri,
    this.backupCodes,
  });

  /// Successful setup (non-TOTP)
  const MfaSetupResult.success()
      : success = true,
        secret = null,
        qrCodeUri = null,
        backupCodes = null;

  /// TOTP setup result
  const MfaSetupResult.totp({
    required this.secret,
    required this.qrCodeUri,
    this.backupCodes,
  }) : success = true;

  /// Whether this is a TOTP setup result
  bool get isTotp => secret != null && qrCodeUri != null;
}
