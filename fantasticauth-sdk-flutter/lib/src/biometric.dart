import 'dart:io';

import 'package:flutter/services.dart';
import 'package:local_auth/local_auth.dart';
import 'package:local_auth_android/local_auth_android.dart';
import 'package:local_auth_ios/local_auth_ios.dart';

import 'exceptions.dart';
import 'session.dart';
import 'storage.dart';

/// Biometric authentication for Vault SDK
/// 
/// Supports:
/// - iOS: Face ID and Touch ID
/// - Android: Fingerprint and Face recognition
class VaultBiometric {
  static VaultBiometric? _instance;

  /// Local authentication instance
  final LocalAuthentication _localAuth;
  
  /// Storage instance
  final VaultStorage _storage;
  
  /// Session instance
  final VaultSession _session;

  VaultBiometric._({
    LocalAuthentication? localAuth,
    VaultStorage? storage,
    VaultSession? session,
  })  : _localAuth = localAuth ?? LocalAuthentication(),
        _storage = storage ?? VaultStorage.instance,
        _session = session ?? VaultSession.instance;

  /// Get or create the singleton instance
  factory VaultBiometric({
    LocalAuthentication? localAuth,
    VaultStorage? storage,
    VaultSession? session,
  }) {
    _instance ??= VaultBiometric._(
      localAuth: localAuth,
      storage: storage,
      session: session,
    );
    return _instance!;
  }

  /// Get the singleton instance
  static VaultBiometric get instance {
    if (_instance == null) {
      throw const VaultBiometricException(
        'VaultBiometric not initialized. Call Vault.initialize() first.',
      );
    }
    return _instance!;
  }

  /// Check if biometric authentication is available on this device
  Future<bool> isAvailable() async {
    try {
      return await _localAuth.isDeviceSupported() &&
             await _localAuth.canCheckBiometrics;
    } on PlatformException catch (e) {
      throw VaultBiometricException(
        'Failed to check biometric availability: ${e.message}',
        code: e.code,
      );
    }
  }

  /// Get available biometric types
  Future<List<BiometricType>> getAvailableTypes() async {
    try {
      return await _localAuth.getAvailableBiometrics();
    } on PlatformException catch (e) {
      throw VaultBiometricException(
        'Failed to get available biometrics: ${e.message}',
        code: e.code,
      );
    }
  }

  /// Get human-readable biometric type name
  Future<String> getBiometricTypeName() async {
    final types = await getAvailableTypes();
    
    if (Platform.isIOS) {
      if (types.contains(BiometricType.face)) {
        return 'Face ID';
      } else if (types.contains(BiometricType.fingerprint)) {
        return 'Touch ID';
      }
    } else if (Platform.isAndroid) {
      if (types.contains(BiometricType.face)) {
        return 'Face Recognition';
      } else if (types.contains(BiometricType.fingerprint)) {
        return 'Fingerprint';
      } else if (types.contains(BiometricType.iris)) {
        return 'Iris Scan';
      }
    }
    
    return 'Biometric Authentication';
  }

  /// Authenticate using biometrics
  /// 
  /// Returns `true` if authentication was successful
  Future<bool> authenticate({
    required String reason,
    bool useErrorDialogs = true,
    bool stickyAuth = false,
    bool sensitiveTransaction = true,
  }) async {
    try {
      final available = await isAvailable();
      if (!available) {
        throw const VaultBiometricException(
          'Biometric authentication is not available on this device',
          hardwareUnavailable: true,
        );
      }

      final isAuthenticated = await _localAuth.authenticate(
        localizedReason: reason,
        authMessages: _buildAuthMessages(),
        options: AuthenticationOptions(
          useErrorDialogs: useErrorDialogs,
          stickyAuth: stickyAuth,
          sensitiveTransaction: sensitiveTransaction,
          biometricOnly: true,
        ),
      );

      return isAuthenticated;
    } on PlatformException catch (e) {
      if (e.code == 'UserCancel' || e.code == 'NotAvailable') {
        throw VaultBiometricException(
          'Authentication cancelled',
          wasCancelled: true,
          code: e.code,
        );
      }
      throw VaultBiometricException(
        'Biometric authentication failed: ${e.message}',
        code: e.code,
      );
    }
  }

  /// Authenticate with fallback to device credentials
  /// 
  /// Returns `true` if authentication was successful
  Future<bool> authenticateWithFallback({
    required String reason,
    bool useErrorDialogs = true,
    bool stickyAuth = false,
  }) async {
    try {
      final available = await isAvailable();
      if (!available) {
        throw const VaultBiometricException(
          'Biometric authentication is not available on this device',
          hardwareUnavailable: true,
        );
      }

      final isAuthenticated = await _localAuth.authenticate(
        localizedReason: reason,
        authMessages: _buildAuthMessages(),
        options: AuthenticationOptions(
          useErrorDialogs: useErrorDialogs,
          stickyAuth: stickyAuth,
          sensitiveTransaction: true,
          biometricOnly: false,
        ),
      );

      return isAuthenticated;
    } on PlatformException catch (e) {
      if (e.code == 'UserCancel') {
        throw VaultBiometricException(
          'Authentication cancelled',
          wasCancelled: true,
          code: e.code,
        );
      }
      throw VaultBiometricException(
        'Authentication failed: ${e.message}',
        code: e.code,
      );
    }
  }

  /// Stop authentication
  Future<bool> stopAuthentication() async {
    try {
      return await _localAuth.stopAuthentication();
    } on PlatformException catch (e) {
      throw VaultBiometricException(
        'Failed to stop authentication: ${e.message}',
        code: e.code,
      );
    }
  }

  /// Build platform-specific authentication messages
  List<AuthMessages> _buildAuthMessages() {
    return [
      const AndroidAuthMessages(
        signInTitle: 'Biometric Authentication',
        cancelButton: 'Cancel',
        biometricHint: 'Verify your identity',
        biometricNotRecognized: 'Not recognized, try again',
        biometricRequiredTitle: 'Biometric authentication required',
        deviceCredentialsRequiredTitle: 'Device credentials required',
        deviceCredentialsSetupDescription: 
            'Please set up device credentials to continue',
        goToSettingsButton: 'Go to Settings',
        goToSettingsDescription: 
            'Please set up biometric authentication in Settings',
      ),
      const IOSAuthMessages(
        cancelButton: 'Cancel',
        goToSettingsButton: 'Go to Settings',
        goToSettingsDescription: 
            'Please set up biometric authentication in Settings',
        lockOut: 'Please re-enable biometric authentication',
      ),
    ];
  }

  // ===== Biometric + Session Integration =====

  /// Check if biometric login is enabled
  Future<bool> isBiometricLoginEnabled() async {
    return _storage.isBiometricEnabled();
  }

  /// Enable biometric login for current user
  /// 
  /// Requires the user to be authenticated first
  Future<void> enableBiometricLogin() async {
    // Check if user is authenticated
    if (!await _session.isAuthenticated()) {
      throw const VaultBiometricException(
        'User must be authenticated to enable biometric login',
        code: 'NOT_AUTHENTICATED',
      );
    }

    // Verify biometric is available
    if (!await isAvailable()) {
      throw const VaultBiometricException(
        'Biometric authentication is not available on this device',
        hardwareUnavailable: true,
      );
    }

    // Authenticate with biometrics to confirm
    final success = await authenticate(
      reason: 'Confirm biometric login setup',
    );

    if (!success) {
      throw const VaultBiometricException(
        'Biometric authentication failed',
        code: 'AUTHENTICATION_FAILED',
      );
    }

    // Store biometric enabled flag
    await _storage.setBiometricEnabled(true);
  }

  /// Disable biometric login
  Future<void> disableBiometricLogin() async {
    await _storage.setBiometricEnabled(false);
  }

  /// Authenticate with biometrics and return session
  /// 
  /// This will authenticate the user using biometrics and return
  /// an active session if biometric login was previously enabled.
  Future<VaultSession?> authenticateWithBiometrics() async {
    // Check if biometric login is enabled
    if (!await isBiometricLoginEnabled()) {
      throw const VaultBiometricException(
        'Biometric login is not enabled',
        code: 'BIOMETRIC_NOT_ENABLED',
      );
    }

    // Check if user has a valid session (tokens stored)
    final token = await _storage.getAccessToken();
    if (token == null) {
      throw const VaultBiometricException(
        'No active session found',
        code: 'NO_SESSION',
      );
    }

    // Authenticate with biometrics
    final typeName = await getBiometricTypeName();
    final success = await authenticate(
      reason: 'Authenticate with $typeName to access your account',
    );

    if (!success) {
      return null;
    }

    // Return the session
    return _session;
  }

  /// Toggle biometric login
  Future<bool> toggleBiometricLogin() async {
    final currentlyEnabled = await isBiometricLoginEnabled();
    
    if (currentlyEnabled) {
      await disableBiometricLogin();
      return false;
    } else {
      await enableBiometricLogin();
      return true;
    }
  }
}

/// Extension for VaultSession to support biometric operations
extension VaultSessionBiometric on VaultSession {
  /// Check if biometric authentication is available
  Future<bool> isBiometricAvailable() async {
    return VaultBiometric.instance.isAvailable();
  }

  /// Enable biometric login for this session
  Future<void> enableBiometric() async {
    return VaultBiometric.instance.enableBiometricLogin();
  }

  /// Disable biometric login for this session
  Future<void> disableBiometric() async {
    return VaultBiometric.instance.disableBiometricLogin();
  }

  /// Check if biometric login is enabled
  Future<bool> isBiometricEnabled() async {
    return VaultBiometric.instance.isBiometricLoginEnabled();
  }
}
