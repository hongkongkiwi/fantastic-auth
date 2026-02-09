import Foundation

// MARK: - User

public struct User: Codable, Identifiable, Equatable {
    public let id: String
    public let email: String
    public let name: String?
    public let avatarUrl: String?
    public let emailVerified: Bool
    public let createdAt: Date
    public let updatedAt: Date
    public let metadata: [String: String]?
    public let roles: [String]
    public let permissions: [String]
    
    public init(
        id: String,
        email: String,
        name: String? = nil,
        avatarUrl: String? = nil,
        emailVerified: Bool = false,
        createdAt: Date = Date(),
        updatedAt: Date = Date(),
        metadata: [String: String]? = nil,
        roles: [String] = [],
        permissions: [String] = []
    ) {
        self.id = id
        self.email = email
        self.name = name
        self.avatarUrl = avatarUrl
        self.emailVerified = emailVerified
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.metadata = metadata
        self.roles = roles
        self.permissions = permissions
    }
    
    enum CodingKeys: String, CodingKey {
        case id
        case email
        case name
        case avatarUrl = "avatar_url"
        case emailVerified = "email_verified"
        case createdAt = "created_at"
        case updatedAt = "updated_at"
        case metadata
        case roles
        case permissions
    }
}

// MARK: - UserUpdateRequest

public struct UserUpdateRequest: Codable {
    public let name: String?
    public let email: String?
    public let metadata: [String: String]?
    
    public init(
        name: String? = nil,
        email: String? = nil,
        metadata: [String: String]? = nil
    ) {
        self.name = name
        self.email = email
        self.metadata = metadata
    }
}

// MARK: - PasswordChangeRequest

public struct PasswordChangeRequest: Codable {
    public let currentPassword: String
    public let newPassword: String
    
    public init(currentPassword: String, newPassword: String) {
        self.currentPassword = currentPassword
        self.newPassword = newPassword
    }
    
    enum CodingKeys: String, CodingKey {
        case currentPassword = "current_password"
        case newPassword = "new_password"
    }
}

// MARK: - AuthResponse

struct AuthResponse: Codable {
    let user: User
    let session: Session
}

// MARK: - LoginRequest

struct LoginRequest: Codable {
    let email: String
    let password: String
    let tenantId: String?
    
    enum CodingKeys: String, CodingKey {
        case email
        case password
        case tenantId = "tenant_id"
    }
}

// MARK: - SignupRequest

struct SignupRequest: Codable {
    let email: String
    let password: String
    let name: String?
    let tenantId: String?
    
    enum CodingKeys: String, CodingKey {
        case email
        case password
        case name
        case tenantId = "tenant_id"
    }
}

// MARK: - TokenVerificationRequest

struct TokenVerificationRequest: Codable {
    let token: String
}
