import 'package:http/http.dart' as http;

import 'api_client.dart';
import 'auth.dart';
import 'biometric.dart';
import 'exceptions.dart';
import 'organization.dart';
import 'session.dart';
import 'storage.dart';

/// Main Vault SDK class
/// 
/// This is the entry point for the Vault SDK. Initialize it with your
/// configuration before using any other SDK features.
/// 
/// ## Example
/// 
/// ```dart
/// void main() {
///   Vault.initialize(
///     apiUrl: 'https://api.vault.dev',
///     tenantId: 'my-tenant',
///   );
/// 
///   // Now you can use the SDK
///   final auth = VaultAuth();
///   final session = VaultSession();
/// }
/// ```
class Vault {
  static Vault? _instance;

  /// Whether the SDK has been initialized
  static bool get isInitialized => _instance != null;

  /// API URL
  final String apiUrl;
  
  /// Tenant ID
  final String? tenantId;
  
  /// Tenant slug
  final String? tenantSlug;
  
  /// API version
  final String apiVersion;
  
  /// Request timeout
  final Duration timeout;
  
  /// Storage options
  final VaultStorageOptions? storageOptions;

  Vault._({
    required this.apiUrl,
    this.tenantId,
    this.tenantSlug,
    this.apiVersion = 'v1',
    this.timeout = const Duration(seconds: 30),
    this.storageOptions,
  }) {
    // Validate API URL
    if (apiUrl.isEmpty) {
      throw const VaultConfigurationException(
        'API URL cannot be empty',
      );
    }

    // Ensure API URL is valid
    Uri? uri;
    try {
      uri = Uri.parse(apiUrl);
    } catch (e) {
      throw VaultConfigurationException(
        'Invalid API URL: $apiUrl',
      );
    }

    if (!uri.isScheme('https') && !uri.isScheme('http')) {
      throw VaultConfigurationException(
        'API URL must use http or https scheme: $apiUrl',
      );
    }
  }

  /// Initialize the Vault SDK
  /// 
  /// Must be called before using any SDK features.
  /// 
  /// Parameters:
  /// - [apiUrl]: The base URL of your Vault API (e.g., 'https://api.vault.dev')
  /// - [tenantId]: Optional tenant ID for multi-tenancy
  /// - [tenantSlug]: Optional tenant slug for multi-tenancy
  /// - [apiVersion]: API version (default: 'v1')
  /// - [timeout]: Request timeout (default: 30 seconds)
  /// - [storageOptions]: Storage configuration options
  /// - [httpClient]: Optional custom HTTP client
  /// 
  /// ## Example
  /// 
  /// ```dart
  /// Vault.initialize(
  ///   apiUrl: 'https://api.vault.dev',
  ///   tenantId: 'my-tenant',
  /// );
  /// ```
  static void initialize({
    required String apiUrl,
    String? tenantId,
    String? tenantSlug,
    String apiVersion = 'v1',
    Duration timeout = const Duration(seconds: 30),
    VaultStorageOptions? storageOptions,
    http.Client? httpClient,
  }) {
    if (_instance != null) {
      throw const VaultConfigurationException(
        'Vault SDK is already initialized. Call Vault.reset() first if you need to reinitialize.',
      );
    }

    _instance = Vault._(
      apiUrl: apiUrl,
      tenantId: tenantId,
      tenantSlug: tenantSlug,
      apiVersion: apiVersion,
      timeout: timeout,
      storageOptions: storageOptions,
    );

    // Build base URL with API version
    final baseUrl = _instance!._buildBaseUrl();

    // Initialize storage
    VaultStorage(
      androidOptions: storageOptions?.androidOptions,
      iosOptions: storageOptions?.iosOptions,
    );

    // Initialize API client
    final apiClient = VaultApiClient(
      baseUrl: baseUrl,
      tenantId: tenantId,
      tenantSlug: tenantSlug,
      client: httpClient,
      timeout: timeout,
    );

    // Initialize session and link it to API client
    final session = VaultSession();
    apiClient.setSession(session);

    // Initialize other singletons
    VaultAuth();
    VaultBiometric();
    VaultOrganizations();
  }

  /// Reset the Vault SDK
  /// 
  /// Clears all singleton instances. Call this before reinitializing
  /// or when the user signs out completely.
  static Future<void> reset() async {
    // Dispose in reverse order of initialization
    VaultOrganizations.instance.dispose();
    VaultBiometric.instance.dispose();
    VaultAuth.instance.dispose();
    
    // Clear session (this also clears storage)
    await VaultSession.instance.signOut();
    VaultSession.instance.dispose();
    
    VaultApiClient.instance.dispose();
    
    _instance = null;
  }

  /// Get the singleton instance
  static Vault get instance {
    if (_instance == null) {
      throw const VaultConfigurationException(
        'Vault SDK not initialized. Call Vault.initialize() first.',
      );
    }
    return _instance!;
  }

  /// Build the base URL for API requests
  String _buildBaseUrl() {
    var baseUrl = apiUrl.replaceAll(RegExp(r'/+$'), '');
    
    // Add API version if not present
    if (!baseUrl.endsWith('/api/$apiVersion')) {
      baseUrl = '$baseUrl/api/$apiVersion';
    }
    
    return baseUrl;
  }

  /// Get the full API URL
  String get fullApiUrl => _buildBaseUrl();

  /// Check if running in development mode
  bool get isDevelopment => apiUrl.contains('localhost') || 
                            apiUrl.contains('127.0.0.1') ||
                            apiUrl.contains('.dev');

  @override
  String toString() => 
      'Vault(apiUrl: $apiUrl, tenantId: $tenantId, version: $apiVersion)';
}

/// Storage configuration options
class VaultStorageOptions {
  /// Android storage options
  final AndroidOptions? androidOptions;
  
  /// iOS storage options
  final IOSOptions? iosOptions;

  const VaultStorageOptions({
    this.androidOptions,
    this.iosOptions,
  });

  /// Default secure storage options
  static const VaultStorageOptions secure = VaultStorageOptions(
    androidOptions: AndroidOptions(
      encryptedSharedPreferences: true,
      keyCipherAlgorithm: KeyCipherAlgorithm.RSA_ECB_PKCS1Padding,
      storageCipherAlgorithm: StorageCipherAlgorithm.AES_GCM_NoPadding,
    ),
    iosOptions: IOSOptions(
      accountName: 'vault_sdk',
      accessibility: KeychainAccessibility.unlocked_this_device,
    ),
  );

  /// Storage options that persist across backups
  static const VaultStorageOptions persistent = VaultStorageOptions(
    androidOptions: AndroidOptions(
      encryptedSharedPreferences: true,
      keyCipherAlgorithm: KeyCipherAlgorithm.RSA_ECB_PKCS1Padding,
      storageCipherAlgorithm: StorageCipherAlgorithm.AES_GCM_NoPadding,
    ),
    iosOptions: IOSOptions(
      accountName: 'vault_sdk',
      accessibility: KeychainAccessibility.this_device_only,
    ),
  );
}

/// Key cipher algorithms for Android
enum KeyCipherAlgorithm {
  RSA_ECB_PKCS1Padding,
}

/// Storage cipher algorithms for Android
enum StorageCipherAlgorithm {
  AES_GCM_NoPadding,
  AES_CBC_PKCS7Padding,
}

/// Android secure storage options
class AndroidOptions {
  /// Use EncryptedSharedPreferences
  final bool encryptedSharedPreferences;
  
  /// Key cipher algorithm
  final KeyCipherAlgorithm keyCipherAlgorithm;
  
  /// Storage cipher algorithm
  final StorageCipherAlgorithm storageCipherAlgorithm;

  const AndroidOptions({
    this.encryptedSharedPreferences = true,
    this.keyCipherAlgorithm = KeyCipherAlgorithm.RSA_ECB_PKCS1Padding,
    this.storageCipherAlgorithm = StorageCipherAlgorithm.AES_GCM_NoPadding,
  });

  /// Convert to flutter_secure_storage options
  flutter_secure_storage.AndroidOptions toSecureStorageOptions() {
    return flutter_secure_storage.AndroidOptions(
      encryptedSharedPreferences: encryptedSharedPreferences,
      keyCipherAlgorithm: _keyCipherAlgorithmString,
      storageCipherAlgorithm: _storageCipherAlgorithmString,
    );
  }

  String get _keyCipherAlgorithmString {
    switch (keyCipherAlgorithm) {
      case KeyCipherAlgorithm.RSA_ECB_PKCS1Padding:
        return 'RSA/ECB/PKCS1Padding';
    }
  }

  String get _storageCipherAlgorithmString {
    switch (storageCipherAlgorithm) {
      case StorageCipherAlgorithm.AES_GCM_NoPadding:
        return 'AES/GCM/NoPadding';
      case StorageCipherAlgorithm.AES_CBC_PKCS7Padding:
        return 'AES/CBC/PKCS7Padding';
    }
  }
}

/// Keychain accessibility options for iOS
enum KeychainAccessibility {
  unlocked_this_device,
  after_first_unlock,
  when_passcode_set_this_device,
  when_unlocked,
  when_unlocked_this_device,
  this_device_only,
}

/// iOS secure storage options
class IOSOptions {
  /// Keychain account name
  final String accountName;
  
  /// Keychain accessibility
  final KeychainAccessibility accessibility;

  const IOSOptions({
    this.accountName = 'vault_sdk',
    this.accessibility = KeychainAccessibility.unlocked_this_device,
  });

  /// Convert to flutter_secure_storage options
  flutter_secure_storage.IOSOptions toSecureStorageOptions() {
    return flutter_secure_storage.IOSOptions(
      accountName: accountName,
      accessibility: _accessibilityString,
    );
  }

  String get _accessibilityString {
    switch (accessibility) {
      case KeychainAccessibility.unlocked_this_device:
        return 'unlocked_this_device';
      case KeychainAccessibility.after_first_unlock:
        return 'after_first_unlock';
      case KeychainAccessibility.when_passcode_set_this_device:
        return 'when_passcode_set_this_device';
      case KeychainAccessibility.when_unlocked:
        return 'when_unlocked';
      case KeychainAccessibility.when_unlocked_this_device:
        return 'when_unlocked_this_device';
      case KeychainAccessibility.this_device_only:
        return 'unlocked_this_device'; // Fallback
    }
  }
}

/// Import flutter_secure_storage types
library flutter_secure_storage;

import 'package:flutter_secure_storage/flutter_secure_storage.dart'
    show AndroidOptions, IOSOptions;
export 'package:flutter_secure_storage/flutter_secure_storage.dart'
    show AndroidOptions, IOSOptions;

// Extension methods to add dispose() to singletons
extension VaultAuthExtension on VaultAuth {
  void dispose() {
    // Clean up if needed
  }
}

extension VaultBiometricExtension on VaultBiometric {
  void dispose() {
    // Clean up if needed
  }
}

extension VaultOrganizationsExtension on VaultOrganizations {
  void dispose() {
    // Clean up if needed
  }
}
