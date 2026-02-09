import Foundation

// MARK: - Session

public struct Session: Codable, Equatable {
    public let accessToken: String
    public let refreshToken: String
    public let expiresAt: Date
    public let tokenType: String
    public let scope: String?
    
    public var isValid: Bool {
        return Date() < expiresAt
    }
    
    public var isExpiringSoon: Bool {
        let fiveMinutes: TimeInterval = 5 * 60
        return Date().addingTimeInterval(fiveMinutes) >= expiresAt
    }
    
    public init(
        accessToken: String,
        refreshToken: String,
        expiresAt: Date,
        tokenType: String = "Bearer",
        scope: String? = nil
    ) {
        self.accessToken = accessToken
        self.refreshToken = refreshToken
        self.expiresAt = expiresAt
        self.tokenType = tokenType
        self.scope = scope
    }
    
    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case refreshToken = "refresh_token"
        case expiresAt = "expires_at"
        case tokenType = "token_type"
        case scope
    }
}

// MARK: - SessionTokens

struct SessionTokens: Codable {
    let accessToken: String
    let refreshToken: String
}

// MARK: - TokenRefreshRequest

struct TokenRefreshRequest: Codable {
    let refreshToken: String
    
    enum CodingKeys: String, CodingKey {
        case refreshToken = "refresh_token"
    }
}

// MARK: - TokenRefreshResponse

struct TokenRefreshResponse: Codable {
    let accessToken: String
    let expiresAt: Date
    let tokenType: String
    
    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case expiresAt = "expires_at"
        case tokenType = "token_type"
    }
}

// MARK: - OAuthProvider

public enum OAuthProvider: String, Codable, CaseIterable {
    case google = "google"
    case apple = "apple"
    case microsoft = "microsoft"
    case github = "github"
    case facebook = "facebook"
    
    public var displayName: String {
        switch self {
        case .google: return "Google"
        case .apple: return "Apple"
        case .microsoft: return "Microsoft"
        case .github: return "GitHub"
        case .facebook: return "Facebook"
        }
    }
    
    public var iconName: String {
        switch self {
        case .google: return "google"
        case .apple: return "apple"
        case .microsoft: return "microsoft"
        case .github: return "github"
        case .facebook: return "facebook"
        }
    }
}

// MARK: - OAuthRequest

struct OAuthRequest: Codable {
    let provider: String
    let redirectUri: String
    let state: String
    let tenantId: String?
    
    enum CodingKeys: String, CodingKey {
        case provider
        case redirectUri = "redirect_uri"
        case state
        case tenantId = "tenant_id"
    }
}

// MARK: - OAuthCallbackRequest

struct OAuthCallbackRequest: Codable {
    let code: String
    let state: String
    let tenantId: String?
    
    enum CodingKeys: String, CodingKey {
        case code
        case state
        case tenantId = "tenant_id"
    }
}

// MARK: - MFAMethod

public enum MFAMethod: String, Codable, CaseIterable {
    case totp = "totp"
    case sms = "sms"
    case email = "email"
    case push = "push"
    
    public var displayName: String {
        switch self {
        case .totp: return "Authenticator App"
        case .sms: return "SMS"
        case .email: return "Email"
        case .push: return "Push Notification"
        }
    }
}

// MARK: - MFAEnableRequest

struct MFAEnableRequest: Codable {
    let method: String
}

// MARK: - MFAEnableResponse

struct MFAEnableResponse: Codable {
    let secret: String?
    let qrCodeUri: String?
    let backupCodes: [String]?
    
    enum CodingKeys: String, CodingKey {
        case secret
        case qrCodeUri = "qr_code_uri"
        case backupCodes = "backup_codes"
    }
}

// MARK: - MFAVerifyRequest

struct MFAVerifyRequest: Codable {
    let code: String
    let method: String?
    
    enum CodingKeys: String, CodingKey {
        case code
        case method
    }
}

// MARK: - MFADisableRequest

struct MFADisableRequest: Codable {
    let code: String
    let method: String
    
    enum CodingKeys: String, CodingKey {
        case code
        case method
    }
}
