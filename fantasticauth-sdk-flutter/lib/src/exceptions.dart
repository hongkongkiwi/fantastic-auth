/// Exception types for Vault SDK

/// Base exception for all Vault SDK errors
class VaultException implements Exception {
  /// Error message
  final String message;
  
  /// Error code
  final String? code;
  
  /// HTTP status code if applicable
  final int? statusCode;
  
  /// Additional error details
  final Map<String, dynamic>? details;

  const VaultException(
    this.message, {
    this.code,
    this.statusCode,
    this.details,
  });

  @override
  String toString() {
    final buffer = StringBuffer('VaultException: $message');
    if (code != null) buffer.write(' (code: $code)');
    if (statusCode != null) buffer.write(' [HTTP $statusCode]');
    return buffer.toString();
  }
}

/// Exception for authentication failures
class VaultAuthException extends VaultException {
  const VaultAuthException(
    super.message, {
    super.code,
    super.statusCode,
    super.details,
  });
}

/// Exception for network-related errors
class VaultNetworkException extends VaultException {
  /// Original error if available
  final dynamic originalError;

  const VaultNetworkException(
    super.message, {
    this.originalError,
    super.code,
    super.statusCode,
  });
}

/// Exception for validation errors
class VaultValidationException extends VaultException {
  /// Field-specific validation errors
  final Map<String, List<String>>? fieldErrors;

  const VaultValidationException(
    super.message, {
    this.fieldErrors,
    super.code = 'VALIDATION_ERROR',
    super.statusCode = 400,
  });
}

/// Exception for session-related errors
class VaultSessionException extends VaultException {
  const VaultSessionException(
    super.message, {
    super.code,
    super.statusCode,
  });
}

/// Exception thrown when token refresh fails
class VaultTokenRefreshException extends VaultSessionException {
  const VaultTokenRefreshException([
    super.message = 'Failed to refresh access token',
  ]) : super(
    code: 'TOKEN_REFRESH_FAILED',
    statusCode: 401,
  );
}

/// Exception thrown when the session has expired
class VaultSessionExpiredException extends VaultSessionException {
  const VaultSessionExpiredException([
    super.message = 'Session has expired',
  ]) : super(
    code: 'SESSION_EXPIRED',
    statusCode: 401,
  );
}

/// Exception for biometric authentication failures
class VaultBiometricException extends VaultException {
  /// Whether the user cancelled the biometric prompt
  final bool wasCancelled;
  
  /// Whether biometric hardware is unavailable
  final bool hardwareUnavailable;

  const VaultBiometricException(
    super.message, {
    this.wasCancelled = false,
    this.hardwareUnavailable = false,
    super.code,
  });
}

/// Exception for organization-related errors
class VaultOrganizationException extends VaultException {
  const VaultOrganizationException(
    super.message, {
    super.code,
    super.statusCode,
  });
}

/// Exception for storage-related errors
class VaultStorageException extends VaultException {
  const VaultStorageException(
    super.message, {
    super.code,
  });
}

/// Exception for rate limiting
class VaultRateLimitException extends VaultException {
  /// Unix timestamp when the rate limit resets
  final int? resetTimestamp;
  
  /// Number of seconds until rate limit resets
  int? get secondsUntilReset {
    if (resetTimestamp == null) return null;
    final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    final diff = resetTimestamp! - now;
    return diff > 0 ? diff : 0;
  }

  const VaultRateLimitException(
    super.message, {
    this.resetTimestamp,
    super.code = 'RATE_LIMIT_EXCEEDED',
    super.statusCode = 429,
  });
}

/// Exception for MFA-related errors
class VaultMfaException extends VaultException {
  const VaultMfaException(
    super.message, {
    super.code,
    super.statusCode = 403,
  });
}

/// Exception thrown when MFA is required but not provided
class VaultMfaRequiredException extends VaultMfaException {
  /// Available MFA methods
  final List<String> availableMethods;

  const VaultMfaRequiredException({
    this.availableMethods = const [],
  }) : super(
    'Multi-factor authentication required',
    code: 'MFA_REQUIRED',
  );
}

/// Exception thrown when MFA code is invalid
class VaultMfaInvalidCodeException extends VaultMfaException {
  const VaultMfaInvalidCodeException([
    super.message = 'Invalid MFA code',
  ]) : super(code: 'MFA_INVALID_CODE');
}

/// Exception for configuration errors
class VaultConfigurationException extends VaultException {
  const VaultConfigurationException(
    super.message, {
    super.code = 'CONFIGURATION_ERROR',
  });
}

/// Exception for OAuth-related errors
class VaultOAuthException extends VaultException {
  /// OAuth provider that caused the error
  final String? provider;

  const VaultOAuthException(
    super.message, {
    this.provider,
    super.code,
  });
}
