import Foundation
import Combine

/// Represents an organization in Vault.
///
/// Organizations are used for B2B multi-tenancy, allowing users to belong
/// to multiple organizations with different roles.
public struct VaultOrganization: Codable, Equatable, Identifiable, Sendable {
    /// The unique identifier for the organization.
    public let id: String
    
    /// The organization name.
    public let name: String
    
    /// The organization slug (unique identifier in URLs).
    public let slug: String
    
    /// The organization's logo URL.
    public let logoUrl: String?
    
    /// The primary color for the organization's branding.
    public let primaryColor: String?
    
    /// Whether the organization is active.
    public let isActive: Bool
    
    /// The organization's metadata.
    public let metadata: [String: String]?
    
    /// When the organization was created.
    public let createdAt: Date
    
    /// Coding keys for decoding.
    enum CodingKeys: String, CodingKey {
        case id
        case name
        case slug
        case logoUrl = "logo_url"
        case primaryColor = "primary_color"
        case isActive = "is_active"
        case metadata
        case createdAt = "created_at"
    }
}

// MARK: - Organizations Service

/// Service for managing organization-related operations.
public actor VaultOrganizations {
    
    // MARK: - Properties
    
    private let apiClient: APIClient
    private let session: VaultSession
    
    /// The currently active organization ID.
    private var activeOrganizationId: String? {
        didSet {
            UserDefaults.standard.set(activeOrganizationId, forKey: "com.vault.active_organization")
        }
    }
    
    /// Publisher for organization changes.
    nonisolated private let organizationSubject = CurrentValueSubject<VaultOrganization?, Never>(nil)
    
    /// Publisher that emits when the active organization changes.
    nonisolated public var activeOrganizationPublisher: AnyPublisher<VaultOrganization?, Never> {
        organizationSubject.eraseToAnyPublisher()
    }
    
    // MARK: - Initialization
    
    init(apiClient: APIClient, session: VaultSession) {
        self.apiClient = apiClient
        self.session = session
        
        // Restore active organization from UserDefaults
        self.activeOrganizationId = UserDefaults.standard.string(forKey: "com.vault.active_organization")
    }
    
    // MARK: - Organization Management
    
    /// Lists all organizations the current user belongs to.
    ///
    /// - Returns: Array of organizations with membership info
    /// - Throws: `VaultError` if the request fails
    public func list() async throws -> [VaultOrganizationMembership] {
        let response: OrganizationsResponse = try await apiClient.get(path: "/v1/organizations")
        
        // Mark the active organization
        return response.organizations.map { org in
            VaultOrganizationMembership(
                id: org.id,
                name: org.name,
                slug: org.slug,
                role: OrganizationRole(rawValue: org.role) ?? .member,
                isActive: org.id == activeOrganizationId
            )
        }
    }
    
    /// Gets details for a specific organization.
    ///
    /// - Parameter id: The organization ID
    /// - Returns: The organization details
    /// - Throws: `VaultError` if the request fails
    public func get(id: String) async throws -> VaultOrganization {
        let response: OrganizationDetailResponse = try await apiClient.get(
            path: "/v1/organizations/\(id)"
        )
        return response.organization
    }
    
    /// Creates a new organization.
    ///
    /// - Parameters:
    ///   - name: The organization name
    ///   - slug: Optional slug (auto-generated if not provided)
    ///   - metadata: Optional metadata
    /// - Returns: The created organization
    /// - Throws: `VaultError` if creation fails
    public func create(
        name: String,
        slug: String? = nil,
        metadata: [String: String]? = nil
    ) async throws -> VaultOrganization {
        let request = CreateOrganizationRequest(
            name: name,
            slug: slug,
            metadata: metadata
        )
        let response: OrganizationDetailResponse = try await apiClient.post(
            path: "/v1/organizations",
            body: request
        )
        return response.organization
    }
    
    /// Updates an organization.
    ///
    /// - Parameters:
    ///   - id: The organization ID
    ///   - name: Optional new name
    ///   - logoUrl: Optional logo URL
    ///   - primaryColor: Optional primary color
    ///   - metadata: Optional metadata
    /// - Returns: The updated organization
    /// - Throws: `VaultError` if the update fails
    public func update(
        id: String,
        name: String? = nil,
        logoUrl: String? = nil,
        primaryColor: String? = nil,
        metadata: [String: String]? = nil
    ) async throws -> VaultOrganization {
        let request = UpdateOrganizationRequest(
            name: name,
            logoUrl: logoUrl,
            primaryColor: primaryColor,
            metadata: metadata
        )
        let response: OrganizationDetailResponse = try await apiClient.patch(
            path: "/v1/organizations/\(id)",
            body: request
        )
        return response.organization
    }
    
    /// Deletes an organization.
    ///
    /// - Parameter id: The organization ID
    /// - Throws: `VaultError` if deletion fails
    public func delete(id: String) async throws {
        let _: EmptyResponse = try await apiClient.delete(
            path: "/v1/organizations/\(id)"
        )
        
        // Clear active organization if it was deleted
        if activeOrganizationId == id {
            activeOrganizationId = nil
            organizationSubject.send(nil)
        }
    }
    
    // MARK: - Active Organization
    
    /// Sets the active organization.
    ///
    /// The active organization is used for all subsequent API calls
    /// that require organization context.
    ///
    /// - Parameter id: The organization ID to activate
    /// - Throws: `VaultError` if the organization is not found
    public func setActive(_ id: String) async throws {
        // Verify the user belongs to this organization
        let orgs = try await list()
        guard orgs.contains(where: { $0.id == id }) else {
            throw VaultError.notFound
        }
        
        activeOrganizationId = id
        
        // Fetch and publish the organization details
        if let org = try? await get(id: id) {
            organizationSubject.send(org)
        }
        
        Vault.shared.logger.log("Active organization set: \(id)")
    }
    
    /// Clears the active organization.
    public func clearActive() {
        activeOrganizationId = nil
        organizationSubject.send(nil)
        Vault.shared.logger.log("Active organization cleared")
    }
    
    /// Gets the currently active organization.
    ///
    /// - Returns: The active organization, or `nil` if none is set
    public func getActive() async -> VaultOrganization? {
        guard let id = activeOrganizationId else {
            return nil
        }
        
        return try? await get(id: id)
    }
    
    /// Gets the active organization ID.
    public var activeId: String? {
        activeOrganizationId
    }
    
    // MARK: - Members
    
    /// Lists members of an organization.
    ///
    /// - Parameters:
    ///   - organizationId: The organization ID
    ///   - page: Page number (1-based)
    ///   - limit: Items per page
    /// - Returns: Paginated list of members
    /// - Throws: `VaultError` if the request fails
    public func listMembers(
        organizationId: String,
        page: Int = 1,
        limit: Int = 20
    ) async throws -> PaginatedResponse<OrganizationMember> {
        let response: MembersResponse = try await apiClient.get(
            path: "/v1/organizations/\(organizationId)/members?page=\(page)&limit=\(limit)"
        )
        
        return PaginatedResponse(
            items: response.members,
            total: response.total,
            page: page,
            limit: limit,
            hasMore: response.members.count == limit
        )
    }
    
    /// Invites a new member to an organization.
    ///
    /// - Parameters:
    ///   - email: The email address to invite
    ///   - role: The role to assign
    ///   - organizationId: The organization ID
    /// - Throws: `VaultError` if the invitation fails
    public func inviteMember(
        email: String,
        role: OrganizationRole,
        to organizationId: String
    ) async throws {
        let request = InviteMemberRequest(email: email, role: role.rawValue)
        let _: EmptyResponse = try await apiClient.post(
            path: "/v1/organizations/\(organizationId)/invitations",
            body: request
        )
        
        Vault.shared.logger.log("Invited \(email) to organization \(organizationId)")
    }
    
    /// Updates a member's role.
    ///
    /// - Parameters:
    ///   - userId: The user ID
    ///   - role: The new role
    ///   - organizationId: The organization ID
    /// - Throws: `VaultError` if the update fails
    public func updateMemberRole(
        userId: String,
        role: OrganizationRole,
        in organizationId: String
    ) async throws {
        let request = UpdateRoleRequest(role: role.rawValue)
        let _: EmptyResponse = try await apiClient.patch(
            path: "/v1/organizations/\(organizationId)/members/\(userId)",
            body: request
        )
        
        Vault.shared.logger.log("Updated role for \(userId) to \(role.rawValue)")
    }
    
    /// Removes a member from an organization.
    ///
    /// - Parameters:
    ///   - userId: The user ID
    ///   - organizationId: The organization ID
    /// - Throws: `VaultError` if removal fails
    public func removeMember(
        userId: String,
        from organizationId: String
    ) async throws {
        let _: EmptyResponse = try await apiClient.delete(
            path: "/v1/organizations/\(organizationId)/members/\(userId)"
        )
        
        Vault.shared.logger.log("Removed \(userId) from organization \(organizationId)")
    }
    
    // MARK: - Invitations
    
    /// Lists pending invitations for an organization.
    ///
    /// - Parameter organizationId: The organization ID
    /// - Returns: Array of pending invitations
    /// - Throws: `VaultError` if the request fails
    public func listInvitations(organizationId: String) async throws -> [OrganizationInvitation] {
        let response: InvitationsResponse = try await apiClient.get(
            path: "/v1/organizations/\(organizationId)/invitations"
        )
        return response.invitations
    }
    
    /// Cancels a pending invitation.
    ///
    /// - Parameters:
    ///   - invitationId: The invitation ID
    ///   - organizationId: The organization ID
    /// - Throws: `VaultError` if cancellation fails
    public func cancelInvitation(
        _ invitationId: String,
        in organizationId: String
    ) async throws {
        let _: EmptyResponse = try await apiClient.delete(
            path: "/v1/organizations/\(organizationId)/invitations/\(invitationId)"
        )
    }
    
    /// Accepts an organization invitation.
    ///
    /// - Parameter token: The invitation token
    /// - Returns: The organization joined
    /// - Throws: `VaultError` if acceptance fails
    public func acceptInvitation(token: String) async throws -> VaultOrganization {
        let request = AcceptInvitationRequest(token: token)
        let response: OrganizationDetailResponse = try await apiClient.post(
            path: "/v1/organizations/invitations/accept",
            body: request,
            requiresAuth: true
        )
        return response.organization
    }
    
    /// Leaves an organization.
    ///
    /// - Parameter organizationId: The organization to leave
    /// - Throws: `VaultError` if leaving fails
    public func leave(organizationId: String) async throws {
        let _: EmptyResponse = try await apiClient.post(
            path: "/v1/organizations/\(organizationId)/leave",
            body: EmptyRequest()
        )
        
        // Clear active organization if it was left
        if activeOrganizationId == organizationId {
            activeOrganizationId = nil
            organizationSubject.send(nil)
        }
    }
}

// MARK: - Response Types

internal struct OrganizationsResponse: Decodable {
    let organizations: [OrganizationWithRole]
}

internal struct OrganizationWithRole: Decodable {
    let id: String
    let name: String
    let slug: String
    let role: String
}

internal struct OrganizationDetailResponse: Decodable {
    let organization: VaultOrganization
}

internal struct CreateOrganizationRequest: Encodable {
    let name: String
    let slug: String?
    let metadata: [String: String]?
}

internal struct UpdateOrganizationRequest: Encodable {
    let name: String?
    let logoUrl: String?
    let primaryColor: String?
    let metadata: [String: String]?
}

internal struct MembersResponse: Decodable {
    let members: [OrganizationMember]
    let total: Int
}

internal struct InviteMemberRequest: Encodable {
    let email: String
    let role: String
}

internal struct UpdateRoleRequest: Encodable {
    let role: String
}

internal struct InvitationsResponse: Decodable {
    let invitations: [OrganizationInvitation]
}

internal struct AcceptInvitationRequest: Encodable {
    let token: String
}

// MARK: - Public Types

/// Represents a member of an organization.
public struct OrganizationMember: Codable, Equatable, Identifiable, Sendable {
    public let id: String
    public let userId: String
    public let email: String
    public let firstName: String?
    public let lastName: String?
    public let role: OrganizationRole
    public let joinedAt: Date
}

/// Represents a pending organization invitation.
public struct OrganizationInvitation: Codable, Equatable, Identifiable, Sendable {
    public let id: String
    public let email: String
    public let role: OrganizationRole
    public let invitedBy: String
    public let expiresAt: Date
    public let createdAt: Date
}

/// A generic paginated response.
public struct PaginatedResponse<T: Sendable>: Sendable {
    public let items: [T]
    public let total: Int
    public let page: Int
    public let limit: Int
    public let hasMore: Bool
}
