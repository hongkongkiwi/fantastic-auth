import Foundation

// MARK: - Organization

public struct Organization: Codable, Identifiable, Equatable {
    public let id: String
    public let name: String
    public let slug: String
    public let logoUrl: String?
    public let description: String?
    public let website: String?
    public let createdAt: Date
    public let updatedAt: Date
    public let metadata: [String: String]?
    public let settings: OrganizationSettings?
    public let memberCount: Int
    public let role: OrganizationRole
    
    public init(
        id: String,
        name: String,
        slug: String,
        logoUrl: String? = nil,
        description: String? = nil,
        website: String? = nil,
        createdAt: Date = Date(),
        updatedAt: Date = Date(),
        metadata: [String: String]? = nil,
        settings: OrganizationSettings? = nil,
        memberCount: Int = 0,
        role: OrganizationRole = .member
    ) {
        self.id = id
        self.name = name
        self.slug = slug
        self.logoUrl = logoUrl
        self.description = description
        self.website = website
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.metadata = metadata
        self.settings = settings
        self.memberCount = memberCount
        self.role = role
    }
    
    enum CodingKeys: String, CodingKey {
        case id
        case name
        case slug
        case logoUrl = "logo_url"
        case description
        case website
        case createdAt = "created_at"
        case updatedAt = "updated_at"
        case metadata
        case settings
        case memberCount = "member_count"
        case role
    }
}

// MARK: - OrganizationSettings

public struct OrganizationSettings: Codable, Equatable {
    public let mfaRequired: Bool
    public let ssoEnabled: Bool
    public let allowSignups: Bool
    public let allowedDomains: [String]?
    public let sessionDuration: Int?
    
    public init(
        mfaRequired: Bool = false,
        ssoEnabled: Bool = false,
        allowSignups: Bool = true,
        allowedDomains: [String]? = nil,
        sessionDuration: Int? = nil
    ) {
        self.mfaRequired = mfaRequired
        self.ssoEnabled = ssoEnabled
        self.allowSignups = allowSignups
        self.allowedDomains = allowedDomains
        self.sessionDuration = sessionDuration
    }
    
    enum CodingKeys: String, CodingKey {
        case mfaRequired = "mfa_required"
        case ssoEnabled = "sso_enabled"
        case allowSignups = "allow_signups"
        case allowedDomains = "allowed_domains"
        case sessionDuration = "session_duration"
    }
}

// MARK: - OrganizationRole

public enum OrganizationRole: String, Codable, CaseIterable {
    case owner = "owner"
    case admin = "admin"
    case member = "member"
    case viewer = "viewer"
    
    public var displayName: String {
        switch self {
        case .owner: return "Owner"
        case .admin: return "Admin"
        case .member: return "Member"
        case .viewer: return "Viewer"
        }
    }
    
    public var permissions: [String] {
        switch self {
        case .owner:
            return ["*"]
        case .admin:
            return [
                "org:read",
                "org:update",
                "org:members:read",
                "org:members:write",
                "org:members:delete",
                "org:settings:read",
                "org:settings:write",
                "org:invites:write"
            ]
        case .member:
            return [
                "org:read",
                "org:members:read",
                "org:settings:read"
            ]
        case .viewer:
            return [
                "org:read"
            ]
        }
    }
    
    public var canManageMembers: Bool {
        return self == .owner || self == .admin
    }
    
    public var canManageSettings: Bool {
        return self == .owner || self == .admin
    }
}

// MARK: - OrganizationMember

public struct OrganizationMember: Codable, Identifiable, Equatable {
    public let id: String
    public let userId: String
    public let email: String
    public let name: String?
    public let avatarUrl: String?
    public let role: OrganizationRole
    public let joinedAt: Date
    public let lastActiveAt: Date?
    
    public init(
        id: String,
        userId: String,
        email: String,
        name: String? = nil,
        avatarUrl: String? = nil,
        role: OrganizationRole = .member,
        joinedAt: Date = Date(),
        lastActiveAt: Date? = nil
    ) {
        self.id = id
        self.userId = userId
        self.email = email
        self.name = name
        self.avatarUrl = avatarUrl
        self.role = role
        self.joinedAt = joinedAt
        self.lastActiveAt = lastActiveAt
    }
    
    enum CodingKeys: String, CodingKey {
        case id
        case userId = "user_id"
        case email
        case name
        case avatarUrl = "avatar_url"
        case role
        case joinedAt = "joined_at"
        case lastActiveAt = "last_active_at"
    }
}

// MARK: - OrganizationSwitchRequest

struct OrganizationSwitchRequest: Codable {
    let organizationId: String
    
    enum CodingKeys: String, CodingKey {
        case organizationId = "organization_id"
    }
}

// MARK: - OrganizationListResponse

struct OrganizationListResponse: Codable {
    let organizations: [Organization]
    let total: Int
}

// MARK: - OrganizationInviteRequest

public struct OrganizationInviteRequest: Codable {
    public let email: String
    public let role: OrganizationRole
    
    public init(email: String, role: OrganizationRole = .member) {
        self.email = email
        self.role = role
    }
}

// MARK: - OrganizationUpdateRequest

public struct OrganizationUpdateRequest: Codable {
    public let name: String?
    public let description: String?
    public let website: String?
    public let logoUrl: String?
    public let metadata: [String: String]?
    
    public init(
        name: String? = nil,
        description: String? = nil,
        website: String? = nil,
        logoUrl: String? = nil,
        metadata: [String: String]? = nil
    ) {
        self.name = name
        self.description = description
        self.website = website
        self.logoUrl = logoUrl
        self.metadata = metadata
    }
    
    enum CodingKeys: String, CodingKey {
        case name
        case description
        case website
        case logoUrl = "logo_url"
        case metadata
    }
}
