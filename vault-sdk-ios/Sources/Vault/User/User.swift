import Foundation

/// A Vault user.
///
/// This represents an authenticated user with their profile information
/// and organization memberships.
public struct VaultUser: Codable, Equatable, Identifiable, Sendable {
    /// The unique identifier for the user.
    public let id: String
    
    /// The user's email address.
    public let email: String
    
    /// The user's first name.
    public let firstName: String?
    
    /// The user's last name.
    public let lastName: String?
    
    /// Whether the user's email has been verified.
    public let emailVerified: Bool
    
    /// The URL of the user's profile image.
    public let profileImageUrl: String?
    
    /// When the user was created.
    public let createdAt: Date
    
    /// When the user was last updated.
    public let updatedAt: Date
    
    /// The user's organization memberships.
    public var organizations: [VaultOrganizationMembership]
    
    /// The user's full name.
    public var fullName: String {
        [firstName, lastName].compactMap { $0 }.joined(separator: " ")
    }
    
    /// The user's initials for avatar display.
    public var initials: String {
        let first = firstName?.prefix(1) ?? ""
        let last = lastName?.prefix(1) ?? ""
        return "\(first)\(last)".uppercased()
    }
    
    /// Whether the user is a member of any organizations.
    public var hasOrganizations: Bool {
        !organizations.isEmpty
    }
    
    /// Coding keys for decoding.
    enum CodingKeys: String, CodingKey {
        case id
        case email
        case firstName
        case lastName
        case emailVerified
        case profileImageUrl
        case createdAt
        case updatedAt
        case organizations
    }
    
    /// Creates a new user instance.
    public init(
        id: String,
        email: String,
        firstName: String? = nil,
        lastName: String? = nil,
        emailVerified: Bool = false,
        profileImageUrl: String? = nil,
        createdAt: Date = Date(),
        updatedAt: Date = Date(),
        organizations: [VaultOrganizationMembership] = []
    ) {
        self.id = id
        self.email = email
        self.firstName = firstName
        self.lastName = lastName
        self.emailVerified = emailVerified
        self.profileImageUrl = profileImageUrl
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.organizations = organizations
    }
}

// MARK: - Organization Membership

/// Represents a user's membership in an organization.
public struct VaultOrganizationMembership: Codable, Equatable, Identifiable, Sendable {
    /// The organization ID.
    public let id: String
    
    /// The organization name.
    public let name: String
    
    /// The organization slug.
    public let slug: String
    
    /// The user's role in the organization.
    public let role: OrganizationRole
    
    /// Whether this is the currently active organization.
    public var isActive: Bool
    
    /// Coding keys for decoding.
    enum CodingKeys: String, CodingKey {
        case id
        case name
        case slug
        case role
        case isActive = "is_active"
    }
    
    /// Creates a new membership instance.
    public init(
        id: String,
        name: String,
        slug: String,
        role: OrganizationRole,
        isActive: Bool = false
    ) {
        self.id = id
        self.name = name
        self.slug = slug
        self.role = role
        self.isActive = isActive
    }
}

// MARK: - Organization Role

/// The role a user has in an organization.
public enum OrganizationRole: String, Codable, Sendable, CaseIterable {
    /// Owner of the organization with full control.
    case owner = "owner"
    
    /// Administrator with most permissions except critical ones.
    case admin = "admin"
    
    /// Member with standard permissions.
    case member = "member"
    
    /// Guest with limited permissions.
    case guest = "guest"
    
    /// The display name for the role.
    public var displayName: String {
        switch self {
        case .owner: return "Owner"
        case .admin: return "Admin"
        case .member: return "Member"
        case .guest: return "Guest"
        }
    }
    
    /// Whether this role can manage other members.
    public var canManageMembers: Bool {
        self == .owner || self == .admin
    }
    
    /// Whether this role can manage billing.
    public var canManageBilling: Bool {
        self == .owner
    }
    
    /// Whether this role can delete the organization.
    public var canDeleteOrganization: Bool {
        self == .owner
    }
}

// MARK: - User Service

/// Service for managing the current user's profile.
public actor VaultUserService {
    
    // MARK: - Properties
    
    private let apiClient: APIClient
    
    // MARK: - Initialization
    
    init(apiClient: APIClient) {
        self.apiClient = apiClient
    }
    
    // MARK: - Profile Management
    
    /// Gets the current user's profile.
    ///
    /// - Returns: The current user
    /// - Throws: `VaultError` if the request fails
    public func getCurrentUser() async throws -> VaultUser {
        let response: UserResponse = try await apiClient.get(path: "/v1/users/me")
        return mapUserResponse(response)
    }
    
    /// Updates the current user's profile.
    ///
    /// - Parameters:
    ///   - firstName: Optional new first name
    ///   - lastName: Optional new last name
    ///   - phoneNumber: Optional phone number
    /// - Returns: The updated user
    /// - Throws: `VaultError` if the update fails
    public func updateProfile(
        firstName: String? = nil,
        lastName: String? = nil,
        phoneNumber: String? = nil
    ) async throws -> VaultUser {
        let request = UpdateProfileRequest(
            firstName: firstName,
            lastName: lastName,
            phoneNumber: phoneNumber
        )
        let response: UserResponse = try await apiClient.patch(
            path: "/v1/users/me",
            body: request
        )
        return mapUserResponse(response)
    }
    
    /// Uploads a new profile image.
    ///
    /// - Parameter imageData: The image data (JPEG or PNG)
    /// - Returns: The updated user with the new profile image URL
    /// - Throws: `VaultError` if the upload fails
    public func uploadProfileImage(_ imageData: Data) async throws -> VaultUser {
        // For now, we'll use a multipart form upload
        // This is a simplified version - in production you'd want more robust handling
        let boundary = UUID().uuidString
        var request = URLRequest(url: URL(string: "\(Vault.shared.configuration?.apiUrl ?? "")/v1/users/me/avatar")!)
        request.httpMethod = "POST"
        request.setValue("multipart/form-data; boundary=\(boundary)", forHTTPHeaderField: "Content-Type")
        
        var body = Data()
        body.append("--\(boundary)\r\n".data(using: .utf8)!)
        body.append("Content-Disposition: form-data; name=\"file\"; filename=\"avatar.jpg\"\r\n".data(using: .utf8)!)
        body.append("Content-Type: image/jpeg\r\n\r\n".data(using: .utf8)!)
        body.append(imageData)
        body.append("\r\n".data(using: .utf8)!)
        body.append("--\(boundary)--\r\n".data(using: .utf8)!)
        
        request.httpBody = body
        
        // Add auth header
        if let token = await Vault.shared.tokenStore.getAccessToken() {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        
        let (data, _) = try await URLSession.shared.data(for: request)
        let response: UserResponse = try JSONDecoder().decode(UserResponse.self, from: data)
        return mapUserResponse(response)
    }
    
    /// Deletes the current user's profile image.
    ///
    /// - Returns: The updated user
    /// - Throws: `VaultError` if the request fails
    public func deleteProfileImage() async throws -> VaultUser {
        let response: UserResponse = try await apiClient.delete(path: "/v1/users/me/avatar")
        return mapUserResponse(response)
    }
    
    // MARK: - User Preferences
    
    /// Gets the current user's preferences.
    ///
    /// - Returns: The user preferences
    /// - Throws: `VaultError` if the request fails
    public func getPreferences() async throws -> UserPreferences {
        let response: PreferencesResponse = try await apiClient.get(path: "/v1/users/me/preferences")
        return response.preferences
    }
    
    /// Updates the current user's preferences.
    ///
    /// - Parameter preferences: The new preferences
    /// - Returns: The updated preferences
    /// - Throws: `VaultError` if the update fails
    public func updatePreferences(_ preferences: UserPreferences) async throws -> UserPreferences {
        let request = UpdatePreferencesRequest(preferences: preferences)
        let response: PreferencesResponse = try await apiClient.patch(
            path: "/v1/users/me/preferences",
            body: request
        )
        return response.preferences
    }
    
    // MARK: - Private Methods
    
    private func mapUserResponse(_ response: UserResponse) -> VaultUser {
        let dateFormatter = ISO8601DateFormatter()
        
        return VaultUser(
            id: response.id,
            email: response.email,
            firstName: response.firstName,
            lastName: response.lastName,
            emailVerified: response.emailVerified,
            createdAt: dateFormatter.date(from: response.createdAt) ?? Date(),
            updatedAt: dateFormatter.date(from: response.updatedAt) ?? Date(),
            organizations: response.organizations?.map { org in
                VaultOrganizationMembership(
                    id: org.id,
                    name: org.name,
                    slug: org.slug,
                    role: OrganizationRole(rawValue: org.role) ?? .member,
                    isActive: false
                )
            } ?? []
        )
    }
}

// MARK: - User Preferences

/// User preferences for the Vault SDK.
public struct UserPreferences: Codable, Equatable, Sendable {
    /// Whether to use biometric authentication.
    public var useBiometric: Bool
    
    /// The user's preferred language.
    public var language: String
    
    /// The user's preferred theme.
    public var theme: Theme
    
    /// Whether to enable notifications.
    public var notificationsEnabled: Bool
    
    /// The user's timezone.
    public var timezone: String
    
    /// Creates default preferences.
    public init(
        useBiometric: Bool = false,
        language: String = "en",
        theme: Theme = .system,
        notificationsEnabled: Bool = true,
        timezone: String = TimeZone.current.identifier
    ) {
        self.useBiometric = useBiometric
        self.language = language
        self.theme = theme
        self.notificationsEnabled = notificationsEnabled
        self.timezone = timezone
    }
}

// MARK: - Theme

/// The color theme preference.
public enum Theme: String, Codable, Sendable, CaseIterable {
    case light = "light"
    case dark = "dark"
    case system = "system"
}

// MARK: - Response Types

internal struct PreferencesResponse: Decodable {
    let preferences: UserPreferences
}

internal struct UpdatePreferencesRequest: Encodable {
    let preferences: UserPreferences
}
