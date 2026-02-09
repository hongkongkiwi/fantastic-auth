/// User model for Vault SDK
class VaultUser {
  /// Unique user ID
  final String id;
  
  /// User email address
  final String email;
  
  /// Whether the email is verified
  final bool emailVerified;
  
  /// User's full name
  final String? name;
  
  /// User's given (first) name
  final String? givenName;
  
  /// User's family (last) name
  final String? familyName;
  
  /// Profile picture URL
  final String? picture;
  
  /// Whether MFA is enabled
  final bool mfaEnabled;
  
  /// List of enabled MFA methods
  final List<String> mfaMethods;
  
  /// OAuth connections
  final List<OAuthConnection> oauthConnections;
  
  /// Account creation timestamp
  final DateTime? createdAt;
  
  /// Last update timestamp
  final DateTime? updatedAt;

  const VaultUser({
    required this.id,
    required this.email,
    required this.emailVerified,
    this.name,
    this.givenName,
    this.familyName,
    this.picture,
    this.mfaEnabled = false,
    this.mfaMethods = const [],
    this.oauthConnections = const [],
    this.createdAt,
    this.updatedAt,
  });

  /// Create a user from JSON
  factory VaultUser.fromJson(Map<String, dynamic> json) {
    return VaultUser(
      id: json['id'] as String,
      email: json['email'] as String,
      emailVerified: json['emailVerified'] as bool? ?? false,
      name: json['name'] as String?,
      givenName: json['givenName'] as String?,
      familyName: json['familyName'] as String?,
      picture: json['picture'] as String?,
      mfaEnabled: json['mfaEnabled'] as bool? ?? false,
      mfaMethods: (json['mfaMethods'] as List<dynamic>?)
          ?.cast<String>() ??
          [],
      oauthConnections: (json['oauthConnections'] as List<dynamic>?)
          ?.map((e) => OAuthConnection.fromJson(e as Map<String, dynamic>))
          .toList() ??
          [],
      createdAt: json['createdAt'] != null
          ? DateTime.parse(json['createdAt'] as String)
          : null,
      updatedAt: json['updatedAt'] != null
          ? DateTime.parse(json['updatedAt'] as String)
          : null,
    );
  }

  /// Convert user to JSON
  Map<String, dynamic> toJson() {
    return {
      'id': id,
      'email': email,
      'emailVerified': emailVerified,
      if (name != null) 'name': name,
      if (givenName != null) 'givenName': givenName,
      if (familyName != null) 'familyName': familyName,
      if (picture != null) 'picture': picture,
      'mfaEnabled': mfaEnabled,
      'mfaMethods': mfaMethods,
      'oauthConnections': oauthConnections.map((e) => e.toJson()).toList(),
      if (createdAt != null) 'createdAt': createdAt!.toIso8601String(),
      if (updatedAt != null) 'updatedAt': updatedAt!.toIso8601String(),
    };
  }

  /// Create a copy of this user with modified fields
  VaultUser copyWith({
    String? id,
    String? email,
    bool? emailVerified,
    String? name,
    String? givenName,
    String? familyName,
    String? picture,
    bool? mfaEnabled,
    List<String>? mfaMethods,
    List<OAuthConnection>? oauthConnections,
    DateTime? createdAt,
    DateTime? updatedAt,
  }) {
    return VaultUser(
      id: id ?? this.id,
      email: email ?? this.email,
      emailVerified: emailVerified ?? this.emailVerified,
      name: name ?? this.name,
      givenName: givenName ?? this.givenName,
      familyName: familyName ?? this.familyName,
      picture: picture ?? this.picture,
      mfaEnabled: mfaEnabled ?? this.mfaEnabled,
      mfaMethods: mfaMethods ?? this.mfaMethods,
      oauthConnections: oauthConnections ?? this.oauthConnections,
      createdAt: createdAt ?? this.createdAt,
      updatedAt: updatedAt ?? this.updatedAt,
    );
  }

  /// Get display name (name or email)
  String get displayName => name ?? email;

  /// Get initials for avatar
  String get initials {
    if (name != null && name!.isNotEmpty) {
      final parts = name!.trim().split(' ');
      if (parts.length > 1) {
        return '${parts.first[0]}${parts.last[0]}'.toUpperCase();
      }
      return name!.substring(0, 1).toUpperCase();
    }
    return email.substring(0, 1).toUpperCase();
  }

  @override
  String toString() => 'VaultUser(id: $id, email: $email, name: $name)';

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;
    return other is VaultUser && other.id == id;
  }

  @override
  int get hashCode => id.hashCode;
}

/// OAuth connection model
class OAuthConnection {
  /// OAuth provider (google, github, etc.)
  final String provider;
  
  /// Provider-specific user ID
  final String providerUserId;
  
  /// Username from provider
  final String? providerUsername;
  
  /// Email from provider
  final String? email;
  
  /// When the connection was created
  final DateTime? connectedAt;

  const OAuthConnection({
    required this.provider,
    required this.providerUserId,
    this.providerUsername,
    this.email,
    this.connectedAt,
  });

  /// Create from JSON
  factory OAuthConnection.fromJson(Map<String, dynamic> json) {
    return OAuthConnection(
      provider: json['provider'] as String,
      providerUserId: json['providerUserId'] as String,
      providerUsername: json['providerUsername'] as String?,
      email: json['email'] as String?,
      connectedAt: json['connectedAt'] != null
          ? DateTime.parse(json['connectedAt'] as String)
          : null,
    );
  }

  /// Convert to JSON
  Map<String, dynamic> toJson() {
    return {
      'provider': provider,
      'providerUserId': providerUserId,
      if (providerUsername != null) 'providerUsername': providerUsername,
      if (email != null) 'email': email,
      if (connectedAt != null) 'connectedAt': connectedAt!.toIso8601String(),
    };
  }

  @override
  String toString() => 
      'OAuthConnection(provider: $provider, username: $providerUsername)';
}

/// OAuth providers enum
enum OAuthProvider {
  google,
  github,
  apple,
  microsoft,
  discord,
  slack,
}

/// Extension for OAuth provider
extension OAuthProviderExtension on OAuthProvider {
  /// Get the provider name
  String get name {
    switch (this) {
      case OAuthProvider.google:
        return 'google';
      case OAuthProvider.github:
        return 'github';
      case OAuthProvider.apple:
        return 'apple';
      case OAuthProvider.microsoft:
        return 'microsoft';
      case OAuthProvider.discord:
        return 'discord';
      case OAuthProvider.slack:
        return 'slack';
    }
  }

  /// Get display name
  String get displayName {
    switch (this) {
      case OAuthProvider.google:
        return 'Google';
      case OAuthProvider.github:
        return 'GitHub';
      case OAuthProvider.apple:
        return 'Apple';
      case OAuthProvider.microsoft:
        return 'Microsoft';
      case OAuthProvider.discord:
        return 'Discord';
      case OAuthProvider.slack:
        return 'Slack';
    }
  }
}

/// MFA method types
enum MfaMethod {
  totp,
  email,
  sms,
  webauthn,
  backupCodes,
}

/// Extension for MFA method
extension MfaMethodExtension on MfaMethod {
  /// Get the method name
  String get name {
    switch (this) {
      case MfaMethod.totp:
        return 'totp';
      case MfaMethod.email:
        return 'email';
      case MfaMethod.sms:
        return 'sms';
      case MfaMethod.webauthn:
        return 'webauthn';
      case MfaMethod.backupCodes:
        return 'backup_codes';
    }
  }

  /// Get display name
  String get displayName {
    switch (this) {
      case MfaMethod.totp:
        return 'Authenticator App';
      case MfaMethod.email:
        return 'Email';
      case MfaMethod.sms:
        return 'SMS';
      case MfaMethod.webauthn:
        return 'Security Key';
      case MfaMethod.backupCodes:
        return 'Backup Codes';
    }
  }
}
