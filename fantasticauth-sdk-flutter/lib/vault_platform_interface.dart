import 'package:plugin_platform_interface/plugin_platform_interface.dart';

/// Platform interface for Vault SDK
abstract class VaultPlatform extends PlatformInterface {
  /// Constructs a VaultPlatform.
  VaultPlatform() : super(token: _token);

  static final Object _token = Object();

  static VaultPlatform _instance = _MethodChannelVault();

  /// The default instance of [VaultPlatform] to use.
  static VaultPlatform get instance => _instance;

  /// Platform-specific implementations should set this with their own
  /// platform-specific class that extends [VaultPlatform] when
  /// they register themselves.
  static set instance(VaultPlatform instance) {
    PlatformInterface.verifyToken(instance, _token);
    _instance = instance;
  }

  /// Get the platform version
  Future<String?> getPlatformVersion() {
    throw UnimplementedError('getPlatformVersion() has not been implemented.');
  }

  /// Check if biometric authentication is available
  Future<bool> isBiometricAvailable() {
    throw UnimplementedError('isBiometricAvailable() has not been implemented.');
  }

  /// Get the biometric type (faceID, touchID, fingerprint, etc.)
  Future<String?> getBiometricType() {
    throw UnimplementedError('getBiometricType() has not been implemented.');
  }

  /// Authenticate with biometrics
  Future<bool> authenticateWithBiometrics({required String reason}) {
    throw UnimplementedError('authenticateWithBiometrics() has not been implemented.');
  }
}

/// Method channel implementation of VaultPlatform
class _MethodChannelVault extends VaultPlatform {
  // This is a placeholder for the actual method channel implementation
  // The actual implementation uses the local_auth plugin directly
  
  @override
  Future<String?> getPlatformVersion() async {
    return '1.0.0';
  }

  @override
  Future<bool> isBiometricAvailable() async {
    return false;
  }

  @override
  Future<String?> getBiometricType() async {
    return 'none';
  }

  @override
  Future<bool> authenticateWithBiometrics({required String reason}) async {
    return false;
  }
}
