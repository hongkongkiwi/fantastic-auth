import 'dart:convert';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import 'exceptions.dart';

/// Secure storage for Vault SDK
/// 
/// Uses platform-specific secure storage:
/// - iOS: Keychain
/// - Android: Keystore (with EncryptedSharedPreferences fallback)
class VaultStorage {
  static VaultStorage? _instance;
  
  /// Storage key prefix
  static const String _keyPrefix = 'vault_sdk_';
  
  /// Secure storage instance
  final FlutterSecureStorage _storage;

  VaultStorage._({
    AndroidOptions? androidOptions,
    IOSOptions? iosOptions,
  }) : _storage = FlutterSecureStorage(
    aOptions: androidOptions ??
        const AndroidOptions(
          encryptedSharedPreferences: true,
          keyCipherAlgorithm: KeyCipherAlgorithm.RSA_ECB_PKCS1Padding,
          storageCipherAlgorithm: StorageCipherAlgorithm.AES_GCM_NoPadding,
        ),
    iOptions: iosOptions ??
        const IOSOptions(
          accountName: 'vault_sdk',
          accessibility: KeychainAccessibility.unlocked_this_device,
        ),
  );

  /// Get or create the singleton instance
  factory VaultStorage({
    AndroidOptions? androidOptions,
    IOSOptions? iosOptions,
  }) {
    _instance ??= VaultStorage._(
      androidOptions: androidOptions,
      iosOptions: iosOptions,
    );
    return _instance!;
  }

  /// Get the singleton instance
  static VaultStorage get instance {
    if (_instance == null) {
      throw const VaultStorageException(
        'VaultStorage not initialized. Call Vault.initialize() first.',
      );
    }
    return _instance!;
  }

  /// Build full storage key
  String _buildKey(String key) => '$_keyPrefix$key';

  /// Store a string value securely
  Future<void> setString(String key, String value) async {
    try {
      await _storage.write(key: _buildKey(key), value: value);
    } catch (e) {
      throw VaultStorageException('Failed to store value: $e');
    }
  }

  /// Get a string value
  Future<String?> getString(String key) async {
    try {
      return await _storage.read(key: _buildKey(key));
    } catch (e) {
      throw VaultStorageException('Failed to read value: $e');
    }
  }

  /// Store a boolean value
  Future<void> setBool(String key, bool value) async {
    await setString(key, value.toString());
  }

  /// Get a boolean value
  Future<bool> getBool(String key, {bool defaultValue = false}) async {
    final value = await getString(key);
    if (value == null) return defaultValue;
    return value.toLowerCase() == 'true';
  }

  /// Store an integer value
  Future<void> setInt(String key, int value) async {
    await setString(key, value.toString());
  }

  /// Get an integer value
  Future<int?> getInt(String key) async {
    final value = await getString(key);
    if (value == null) return null;
    return int.tryParse(value);
  }

  /// Store a JSON object
  Future<void> setJson(String key, Map<String, dynamic> value) async {
    await setString(key, jsonEncode(value));
  }

  /// Get a JSON object
  Future<Map<String, dynamic>?> getJson(String key) async {
    final value = await getString(key);
    if (value == null) return null;
    try {
      return jsonDecode(value) as Map<String, dynamic>;
    } catch (e) {
      throw VaultStorageException('Failed to parse JSON value: $e');
    }
  }

  /// Delete a value
  Future<void> delete(String key) async {
    try {
      await _storage.delete(key: _buildKey(key));
    } catch (e) {
      throw VaultStorageException('Failed to delete value: $e');
    }
  }

  /// Delete all Vault-related values
  Future<void> deleteAll() async {
    try {
      final allData = await _storage.readAll();
      for (final key in allData.keys) {
        if (key.startsWith(_keyPrefix)) {
          await _storage.delete(key: key);
        }
      }
    } catch (e) {
      throw VaultStorageException('Failed to delete all values: $e');
    }
  }

  /// Check if a key exists
  Future<bool> containsKey(String key) async {
    try {
      final value = await _storage.read(key: _buildKey(key));
      return value != null;
    } catch (e) {
      throw VaultStorageException('Failed to check key: $e');
    }
  }

  // ===== Session-specific storage methods =====

  /// Storage key for access token
  static const String _accessTokenKey = 'access_token';
  
  /// Storage key for refresh token
  static const String _refreshTokenKey = 'refresh_token';
  
  /// Storage key for user data
  static const String _userDataKey = 'user_data';
  
  /// Storage key for active organization ID
  static const String _activeOrganizationKey = 'active_organization';
  
  /// Storage key for biometric enabled flag
  static const String _biometricEnabledKey = 'biometric_enabled';
  
  /// Storage key for token expiration
  static const String _tokenExpirationKey = 'token_expiration';

  /// Store access token
  Future<void> setAccessToken(String token) async {
    await setString(_accessTokenKey, token);
  }

  /// Get access token
  Future<String?> getAccessToken() async {
    return getString(_accessTokenKey);
  }

  /// Store refresh token
  Future<void> setRefreshToken(String token) async {
    await setString(_refreshTokenKey, token);
  }

  /// Get refresh token
  Future<String?> getRefreshToken() async {
    return getString(_refreshTokenKey);
  }

  /// Store user data
  Future<void> setUserData(Map<String, dynamic> userData) async {
    await setJson(_userDataKey, userData);
  }

  /// Get user data
  Future<Map<String, dynamic>?> getUserData() async {
    return getJson(_userDataKey);
  }

  /// Store active organization ID
  Future<void> setActiveOrganization(String organizationId) async {
    await setString(_activeOrganizationKey, organizationId);
  }

  /// Get active organization ID
  Future<String?> getActiveOrganization() async {
    return getString(_activeOrganizationKey);
  }

  /// Store biometric enabled flag
  Future<void> setBiometricEnabled(bool enabled) async {
    await setBool(_biometricEnabledKey, enabled);
  }

  /// Get biometric enabled flag
  Future<bool> isBiometricEnabled() async {
    return getBool(_biometricEnabledKey, defaultValue: false);
  }

  /// Store token expiration timestamp
  Future<void> setTokenExpiration(DateTime expiration) async {
    await setInt(_tokenExpirationKey, expiration.millisecondsSinceEpoch);
  }

  /// Get token expiration timestamp
  Future<DateTime?> getTokenExpiration() async {
    final timestamp = await getInt(_tokenExpirationKey);
    if (timestamp == null) return null;
    return DateTime.fromMillisecondsSinceEpoch(timestamp);
  }

  /// Clear all session data
  Future<void> clearSession() async {
    await delete(_accessTokenKey);
    await delete(_refreshTokenKey);
    await delete(_userDataKey);
    await delete(_activeOrganizationKey);
    await delete(_biometricEnabledKey);
    await delete(_tokenExpirationKey);
  }
}
