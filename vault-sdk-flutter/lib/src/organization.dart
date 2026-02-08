import 'api_client.dart';
import 'exceptions.dart';

/// Organization management for Vault SDK
class VaultOrganizations {
  static VaultOrganizations? _instance;

  /// API client
  final VaultApiClient _apiClient;

  VaultOrganizations._({VaultApiClient? apiClient})
      : _apiClient = apiClient ?? VaultApiClient.instance;

  /// Get or create the singleton instance
  factory VaultOrganizations({VaultApiClient? apiClient}) {
    _instance ??= VaultOrganizations._(apiClient: apiClient);
    return _instance!;
  }

  /// Get the singleton instance
  static VaultOrganizations get instance {
    if (_instance == null) {
      throw const VaultOrganizationException(
        'VaultOrganizations not initialized. Call Vault.initialize() first.',
      );
    }
    return _instance!;
  }

  /// List all organizations for current user
  Future<List<Organization>> list() async {
    final response = await _apiClient.get(
      '/organizations',
      authenticated: true,
    );

    if (response is List) {
      return response
          .map((e) => Organization.fromJson(e as Map<String, dynamic>))
          .toList();
    }

    return [];
  }

  /// Get a specific organization
  Future<Organization> get(String organizationId) async {
    final response = await _apiClient.get(
      '/organizations/$organizationId',
      authenticated: true,
    );

    return Organization.fromJson(response as Map<String, dynamic>);
  }

  /// Create a new organization
  Future<Organization> create({
    required String name,
    required String slug,
    String? description,
  }) async {
    final body = <String, dynamic>{
      'name': name,
      'slug': slug,
      if (description != null) 'description': description,
    };

    final response = await _apiClient.post(
      '/organizations',
      body: body,
      authenticated: true,
    );

    return Organization.fromJson(response as Map<String, dynamic>);
  }

  /// Update an organization
  Future<Organization> update(
    String organizationId, {
    String? name,
    String? description,
    String? logoUrl,
    String? website,
  }) async {
    final body = <String, dynamic>{
      if (name != null) 'name': name,
      if (description != null) 'description': description,
      if (logoUrl != null) 'logoUrl': logoUrl,
      if (website != null) 'website': website,
    };

    final response = await _apiClient.patch(
      '/organizations/$organizationId',
      body: body,
      authenticated: true,
    );

    return Organization.fromJson(response as Map<String, dynamic>);
  }

  /// Delete an organization
  Future<void> delete(String organizationId) async {
    await _apiClient.delete(
      '/organizations/$organizationId',
      authenticated: true,
    );
  }

  /// List organization members
  Future<List<OrganizationMember>> listMembers(String organizationId) async {
    final response = await _apiClient.get(
      '/organizations/$organizationId/members',
      authenticated: true,
    );

    if (response is List) {
      return response
          .map((e) => OrganizationMember.fromJson(e as Map<String, dynamic>))
          .toList();
    }

    return [];
  }

  /// Invite a member to organization
  Future<Invitation> inviteMember(
    String organizationId, {
    String? email,
    String? userId,
    OrganizationRole role = OrganizationRole.member,
  }) async {
    if (email == null && userId == null) {
      throw const VaultOrganizationException(
        'Either email or userId must be provided',
        code: 'INVALID_INVITE',
      );
    }

    final body = <String, dynamic>{
      'role': role.name,
      if (email != null) 'email': email,
      if (userId != null) 'userId': userId,
    };

    final response = await _apiClient.post(
      '/organizations/$organizationId/members',
      body: body,
      authenticated: true,
    );

    return Invitation.fromJson(response as Map<String, dynamic>);
  }

  /// Update member role
  Future<OrganizationMember> updateMember(
    String organizationId,
    String userId, {
    required OrganizationRole role,
  }) async {
    final response = await _apiClient.patch(
      '/organizations/$organizationId/members/$userId',
      body: {'role': role.name},
      authenticated: true,
    );

    return OrganizationMember.fromJson(response as Map<String, dynamic>);
  }

  /// Remove a member from organization
  Future<void> removeMember(String organizationId, String userId) async {
    await _apiClient.delete(
      '/organizations/$organizationId/members/$userId',
      authenticated: true,
    );
  }

  /// List pending invitations
  Future<List<Invitation>> listInvitations(String organizationId) async {
    final response = await _apiClient.get(
      '/organizations/$organizationId/invitations',
      authenticated: true,
    );

    if (response is List) {
      return response
          .map((e) => Invitation.fromJson(e as Map<String, dynamic>))
          .toList();
    }

    return [];
  }

  /// Accept an invitation
  Future<Organization> acceptInvitation(String token) async {
    final response = await _apiClient.post(
      '/organizations/invitations/$token/accept',
      authenticated: true,
    );

    return Organization.fromJson(response as Map<String, dynamic>);
  }

  /// Revoke an invitation
  Future<void> revokeInvitation(String organizationId, String invitationId) async {
    await _apiClient.delete(
      '/organizations/$organizationId/invitations/$invitationId',
      authenticated: true,
    );
  }
}

/// Organization model
class Organization {
  /// Organization ID
  final String id;
  
  /// Organization name
  final String name;
  
  /// Organization slug
  final String slug;
  
  /// Description
  final String? description;
  
  /// Logo URL
  final String? logoUrl;
  
  /// Website URL
  final String? website;
  
  /// Current member count
  final int memberCount;
  
  /// Maximum allowed members
  final int? maxMembers;
  
  /// Whether SSO is required
  final bool ssoRequired;
  
  /// Creation timestamp
  final DateTime createdAt;
  
  /// Last update timestamp
  final DateTime updatedAt;

  Organization({
    required this.id,
    required this.name,
    required this.slug,
    this.description,
    this.logoUrl,
    this.website,
    required this.memberCount,
    this.maxMembers,
    required this.ssoRequired,
    required this.createdAt,
    required this.updatedAt,
  });

  /// Create from JSON
  factory Organization.fromJson(Map<String, dynamic> json) {
    return Organization(
      id: json['id'] as String,
      name: json['name'] as String,
      slug: json['slug'] as String,
      description: json['description'] as String?,
      logoUrl: json['logoUrl'] as String?,
      website: json['website'] as String?,
      memberCount: json['memberCount'] as int? ?? 0,
      maxMembers: json['maxMembers'] as int?,
      ssoRequired: json['ssoRequired'] as bool? ?? false,
      createdAt: DateTime.parse(json['createdAt'] as String),
      updatedAt: DateTime.parse(json['updatedAt'] as String),
    );
  }

  /// Convert to JSON
  Map<String, dynamic> toJson() {
    return {
      'id': id,
      'name': name,
      'slug': slug,
      if (description != null) 'description': description,
      if (logoUrl != null) 'logoUrl': logoUrl,
      if (website != null) 'website': website,
      'memberCount': memberCount,
      if (maxMembers != null) 'maxMembers': maxMembers,
      'ssoRequired': ssoRequired,
      'createdAt': createdAt.toIso8601String(),
      'updatedAt': updatedAt.toIso8601String(),
    };
  }

  /// Create a copy with modified fields
  Organization copyWith({
    String? id,
    String? name,
    String? slug,
    String? description,
    String? logoUrl,
    String? website,
    int? memberCount,
    int? maxMembers,
    bool? ssoRequired,
    DateTime? createdAt,
    DateTime? updatedAt,
  }) {
    return Organization(
      id: id ?? this.id,
      name: name ?? this.name,
      slug: slug ?? this.slug,
      description: description ?? this.description,
      logoUrl: logoUrl ?? this.logoUrl,
      website: website ?? this.website,
      memberCount: memberCount ?? this.memberCount,
      maxMembers: maxMembers ?? this.maxMembers,
      ssoRequired: ssoRequired ?? this.ssoRequired,
      createdAt: createdAt ?? this.createdAt,
      updatedAt: updatedAt ?? this.updatedAt,
    );
  }

  @override
  String toString() => 'Organization(id: $id, name: $name, slug: $slug)';
}

/// Organization member model
class OrganizationMember {
  /// Member ID
  final String id;
  
  /// User ID
  final String userId;
  
  /// Member email
  final String email;
  
  /// Member name
  final String? name;
  
  /// Member role
  final OrganizationRole role;
  
  /// Member status
  final MemberStatus status;
  
  /// When the member joined
  final DateTime? joinedAt;

  OrganizationMember({
    required this.id,
    required this.userId,
    required this.email,
    this.name,
    required this.role,
    required this.status,
    this.joinedAt,
  });

  /// Create from JSON
  factory OrganizationMember.fromJson(Map<String, dynamic> json) {
    return OrganizationMember(
      id: json['id'] as String,
      userId: json['userId'] as String,
      email: json['email'] as String,
      name: json['name'] as String?,
      role: OrganizationRole.fromString(json['role'] as String),
      status: MemberStatus.fromString(json['status'] as String),
      joinedAt: json['joinedAt'] != null
          ? DateTime.parse(json['joinedAt'] as String)
          : null,
    );
  }

  /// Convert to JSON
  Map<String, dynamic> toJson() {
    return {
      'id': id,
      'userId': userId,
      'email': email,
      if (name != null) 'name': name,
      'role': role.name,
      'status': status.name,
      if (joinedAt != null) 'joinedAt': joinedAt!.toIso8601String(),
    };
  }

  @override
  String toString() => 
      'OrganizationMember(id: $id, email: $email, role: ${role.name})';
}

/// Invitation model
class Invitation {
  /// Invitation ID
  final String id;
  
  /// Organization ID
  final String organizationId;
  
  /// Email address invited
  final String email;
  
  /// Role assigned
  final OrganizationRole role;
  
  /// Invitation status
  final InvitationStatus status;
  
  /// Token for accepting invitation
  final String token;
  
  /// When the invitation expires
  final DateTime expiresAt;
  
  /// When the invitation was created
  final DateTime createdAt;

  Invitation({
    required this.id,
    required this.organizationId,
    required this.email,
    required this.role,
    required this.status,
    required this.token,
    required this.expiresAt,
    required this.createdAt,
  });

  /// Create from JSON
  factory Invitation.fromJson(Map<String, dynamic> json) {
    return Invitation(
      id: json['id'] as String,
      organizationId: json['organizationId'] as String,
      email: json['email'] as String,
      role: OrganizationRole.fromString(json['role'] as String),
      status: InvitationStatus.fromString(json['status'] as String),
      token: json['token'] as String,
      expiresAt: DateTime.parse(json['expiresAt'] as String),
      createdAt: DateTime.parse(json['createdAt'] as String),
    );
  }

  /// Check if invitation is expired
  bool get isExpired => DateTime.now().isAfter(expiresAt);

  /// Check if invitation is pending
  bool get isPending => status == InvitationStatus.pending;

  @override
  String toString() => 'Invitation(id: $id, email: $email, status: ${status.name})';
}

/// Organization roles
enum OrganizationRole {
  owner,
  admin,
  member,
  guest;

  /// Create from string
  static OrganizationRole fromString(String value) {
    return OrganizationRole.values.firstWhere(
      (e) => e.name == value.toLowerCase(),
      orElse: () => OrganizationRole.member,
    );
  }

  /// Check if this role can manage members
  bool get canManageMembers =>
      this == OrganizationRole.owner || this == OrganizationRole.admin;

  /// Check if this role can delete organization
  bool get canDeleteOrganization => this == OrganizationRole.owner;

  /// Check if this role can manage billing
  bool get canManageBilling =>
      this == OrganizationRole.owner || this == OrganizationRole.admin;
}

/// Member status
enum MemberStatus {
  pending,
  active,
  suspended;

  /// Create from string
  static MemberStatus fromString(String value) {
    return MemberStatus.values.firstWhere(
      (e) => e.name == value.toLowerCase(),
      orElse: () => MemberStatus.pending,
    );
  }
}

/// Invitation status
enum InvitationStatus {
  pending,
  accepted,
  revoked,
  expired;

  /// Create from string
  static InvitationStatus fromString(String value) {
    return InvitationStatus.values.firstWhere(
      (e) => e.name == value.toLowerCase(),
      orElse: () => InvitationStatus.pending,
    );
  }
}
