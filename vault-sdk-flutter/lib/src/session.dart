import 'dart:async';

import 'api_client.dart';
import 'exceptions.dart';
import 'storage.dart';
import 'user.dart';

/// Session management for Vault SDK
class VaultSession {
  static VaultSession? _instance;

  /// Storage instance
  final VaultStorage _storage;
  
  /// API client
  final VaultApiClient _apiClient;
  
  /// Current user cache
  VaultUser? _currentUser;
  
  /// Token refresh timer
  Timer? _refreshTimer;
  
  /// Stream controller for session changes
  final StreamController<SessionState> _stateController = 
      StreamController<SessionState>.broadcast();

  VaultSession._({
    VaultStorage? storage,
    VaultApiClient? apiClient,
  })  : _storage = storage ?? VaultStorage.instance,
        _apiClient = apiClient ?? VaultApiClient.instance;

  /// Get or create the singleton instance
  factory VaultSession({VaultStorage? storage, VaultApiClient? apiClient}) {
    _instance ??= VaultSession._(
      storage: storage,
      apiClient: apiClient,
    );
    return _instance!;
  }

  /// Get the singleton instance
  static VaultSession get instance {
    if (_instance == null) {
      throw const VaultSessionException(
        'VaultSession not initialized. Call Vault.initialize() first.',
      );
    }
    return _instance!;
  }

  /// Stream of session state changes
  Stream<SessionState> get stateStream => _stateController.stream;

  /// Check if user is currently authenticated
  Future<bool> isAuthenticated() async {
    final token = await getToken();
    return token != null;
  }

  /// Get current access token
  Future<String?> getToken() async {
    final token = await _storage.getAccessToken();
    if (token == null) return null;

    // Check if token is expired
    final expiration = await _storage.getTokenExpiration();
    if (expiration != null && DateTime.now().isAfter(expiration)) {
      // Token expired, try to refresh
      try {
        await _refreshToken();
        return _storage.getAccessToken();
      } on VaultTokenRefreshException {
        // Refresh failed, clear session
        await signOut();
        return null;
      }
    }

    return token;
  }

  /// Get current refresh token
  Future<String?> getRefreshToken() async {
    return _storage.getRefreshToken();
  }

  /// Get current user
  Future<VaultUser?> getCurrentUser() async {
    // Return cached user if available
    if (_currentUser != null) {
      return _currentUser;
    }

    // Try to load from storage
    final userData = await _storage.getUserData();
    if (userData != null) {
      _currentUser = VaultUser.fromJson(userData);
      return _currentUser;
    }

    // If we have a token, fetch from API
    if (await isAuthenticated()) {
      try {
        final response = await _apiClient.get('/auth/me');
        if (response != null) {
          _currentUser = VaultUser.fromJson(response);
          await _storage.setUserData(_currentUser!.toJson());
          return _currentUser;
        }
      } on VaultSessionExpiredException {
        await signOut();
      }
    }

    return null;
  }

  /// Update current user
  Future<void> updateCurrentUser(VaultUser user) async {
    _currentUser = user;
    await _storage.setUserData(user.toJson());
  }

  /// Set session from auth response
  Future<void> setSession({
    required String accessToken,
    required String refreshToken,
    required VaultUser user,
    DateTime? tokenExpiration,
  }) async {
    await _storage.setAccessToken(accessToken);
    await _storage.setRefreshToken(refreshToken);
    await _storage.setUserData(user.toJson());
    _currentUser = user;

    // Set token expiration (default to 15 minutes if not provided)
    final expiration = tokenExpiration ??
        DateTime.now().add(const Duration(minutes: 15));
    await _storage.setTokenExpiration(expiration);

    // Setup automatic token refresh
    _setupTokenRefresh(expiration);

    // Notify listeners
    _stateController.add(SessionState.authenticated);
  }

  /// Refresh the access token
  Future<void> _refreshToken() async {
    final refreshToken = await _storage.getRefreshToken();
    if (refreshToken == null) {
      throw const VaultTokenRefreshException();
    }

    try {
      final response = await _apiClient.post(
        '/auth/refresh',
        body: {'refreshToken': refreshToken},
        authenticated: false,
      );

      if (response == null || response['accessToken'] == null) {
        throw const VaultTokenRefreshException();
      }

      await _storage.setAccessToken(response['accessToken'] as String);
      await _storage.setRefreshToken(response['refreshToken'] as String);

      // Update expiration
      final expiresIn = response['expiresIn'] as int? ?? 900;
      final expiration = DateTime.now().add(Duration(seconds: expiresIn));
      await _storage.setTokenExpiration(expiration);

      // Setup next refresh
      _setupTokenRefresh(expiration);

      // Update user if provided
      if (response['user'] != null) {
        final user = VaultUser.fromJson(response['user'] as Map<String, dynamic>);
        await updateCurrentUser(user);
      }
    } on VaultException {
      rethrow;
    } catch (e) {
      throw const VaultTokenRefreshException();
    }
  }

  /// Setup automatic token refresh
  void _setupTokenRefresh(DateTime expiration) {
    _refreshTimer?.cancel();

    // Refresh 2 minutes before expiration
    final refreshTime = expiration.subtract(const Duration(minutes: 2));
    final duration = refreshTime.difference(DateTime.now());

    if (duration.isNegative) {
      // Already expired or very close, refresh now
      unawaited(_refreshToken());
    } else {
      _refreshTimer = Timer(duration, () async {
        try {
          await _refreshToken();
        } catch (e) {
          // Refresh failed, will be handled on next API call
        }
      });
    }
  }

  /// Sign out current user
  Future<void> signOut() async {
    try {
      // Call logout endpoint if authenticated
      if (await isAuthenticated()) {
        await _apiClient.post('/auth/logout', authenticated: true);
      }
    } catch (e) {
      // Ignore errors during logout
    } finally {
      // Always clear local session
      await _clearLocalSession();
    }
  }

  /// Sign out from all devices
  Future<void> signOutAllDevices() async {
    try {
      await _apiClient.delete('/users/me/sessions', authenticated: true);
    } finally {
      await _clearLocalSession();
    }
  }

  /// Clear local session data
  Future<void> _clearLocalSession() async {
    _refreshTimer?.cancel();
    _refreshTimer = null;
    _currentUser = null;
    await _storage.clearSession();
    _stateController.add(SessionState.unauthenticated);
  }

  /// List active sessions
  Future<List<SessionInfo>> listSessions() async {
    final response = await _apiClient.get(
      '/users/me/sessions',
      authenticated: true,
    );

    if (response is List) {
      return response
          .map((e) => SessionInfo.fromJson(e as Map<String, dynamic>))
          .toList();
    }

    return [];
  }

  /// Revoke a specific session
  Future<void> revokeSession(String sessionId) async {
    await _apiClient.delete(
      '/users/me/sessions/$sessionId',
      authenticated: true,
    );
  }

  /// Dispose the session
  void dispose() {
    _refreshTimer?.cancel();
    _stateController.close();
    _instance = null;
  }
}

/// Session state enum
enum SessionState {
  authenticated,
  unauthenticated,
}

/// Session information
class SessionInfo {
  /// Session ID
  final String id;
  
  /// IP address
  final String? ipAddress;
  
  /// User agent string
  final String? userAgent;
  
  /// Device information
  final DeviceInfo? deviceInfo;
  
  /// Whether MFA was verified for this session
  final bool mfaVerified;
  
  /// Session creation time
  final DateTime createdAt;
  
  /// Last activity time
  final DateTime lastActivityAt;
  
  /// Session expiration time
  final DateTime expiresAt;
  
  /// Whether this is the current session
  final bool current;

  SessionInfo({
    required this.id,
    this.ipAddress,
    this.userAgent,
    this.deviceInfo,
    required this.mfaVerified,
    required this.createdAt,
    required this.lastActivityAt,
    required this.expiresAt,
    required this.current,
  });

  /// Create from JSON
  factory SessionInfo.fromJson(Map<String, dynamic> json) {
    return SessionInfo(
      id: json['id'] as String,
      ipAddress: json['ipAddress'] as String?,
      userAgent: json['userAgent'] as String?,
      deviceInfo: json['deviceInfo'] != null
          ? DeviceInfo.fromJson(json['deviceInfo'] as Map<String, dynamic>)
          : null,
      mfaVerified: json['mfaVerified'] as bool? ?? false,
      createdAt: DateTime.parse(json['createdAt'] as String),
      lastActivityAt: DateTime.parse(json['lastActivityAt'] as String),
      expiresAt: DateTime.parse(json['expiresAt'] as String),
      current: json['current'] as bool? ?? false,
    );
  }

  /// Check if session is expired
  bool get isExpired => DateTime.now().isAfter(expiresAt);
}

/// Device information
class DeviceInfo {
  /// Device type (desktop, mobile, tablet)
  final String deviceType;
  
  /// Operating system
  final String os;
  
  /// Browser name
  final String browser;
  
  /// Whether the device is mobile
  final bool isMobile;

  DeviceInfo({
    required this.deviceType,
    required this.os,
    required this.browser,
    required this.isMobile,
  });

  /// Create from JSON
  factory DeviceInfo.fromJson(Map<String, dynamic> json) {
    return DeviceInfo(
      deviceType: json['deviceType'] as String,
      os: json['os'] as String,
      browser: json['browser'] as String,
      isMobile: json['isMobile'] as bool? ?? false,
    );
  }
}

/// Utility to ignore async return value
void unawaited(Future<void> future) {}
