import Foundation

// MARK: - PushNotificationHandler

public class PushNotificationHandler {
    
    // MARK: - Properties
    
    private let vaultClient: VaultClient
    
    // MARK: - Initialization
    
    public init(vaultClient: VaultClient) {
        self.vaultClient = vaultClient
    }
    
    // MARK: - MFA Request Handling
    
    /// Approve an MFA request
    /// - Parameter requestId: The MFA request ID
    public func approveMFARequest(requestId: String) async throws {
        let request = MFAActionRequest(
            requestId: requestId,
            action: "approve",
            timestamp: Date()
        )
        
        try await vaultClient.post("/mfa/push/approve", body: request)
    }
    
    /// Deny an MFA request
    /// - Parameter requestId: The MFA request ID
    public func denyMFARequest(requestId: String) async throws {
        let request = MFAActionRequest(
            requestId: requestId,
            action: "deny",
            timestamp: Date()
        )
        
        try await vaultClient.post("/mfa/push/deny", body: request)
    }
    
    // MARK: - Password Reset
    
    /// Handle password reset from push notification
    /// - Parameters:
    ///   - token: The reset token
    ///   - newPassword: The new password
    public func resetPassword(token: String, newPassword: String) async throws {
        let request = PasswordResetConfirmRequest(
            token: token,
            newPassword: newPassword
        )
        
        try await vaultClient.post("/auth/password/reset/confirm", body: request)
    }
    
    // MARK: - Security Actions
    
    /// Acknowledge a security alert
    /// - Parameter alertId: The alert ID
    public func acknowledgeSecurityAlert(alertId: String) async throws {
        try await vaultClient.post("/security/alerts/\(alertId)/acknowledge", body: EmptyBody())
    }
    
    /// Revoke a specific session
    /// - Parameter sessionId: The session ID to revoke
    public func revokeSession(sessionId: String) async throws {
        try await vaultClient.delete("/auth/sessions/\(sessionId)")
    }
    
    /// Revoke all other sessions
    public func revokeOtherSessions() async throws {
        try await vaultClient.post("/auth/sessions/revoke-others", body: EmptyBody())
    }
}

// MARK: - Request Models

struct MFAActionRequest: Codable {
    let requestId: String
    let action: String
    let timestamp: Date
    
    enum CodingKeys: String, CodingKey {
        case requestId = "request_id"
        case action
        case timestamp
    }
}

struct PasswordResetConfirmRequest: Codable {
    let token: String
    let newPassword: String
    
    enum CodingKeys: String, CodingKey {
        case token
        case newPassword = "new_password"
    }
}

struct EmptyBody: Codable {}

// MARK: - Convenience Extensions

public extension PushNotificationManager {
    
    /// Approve MFA request with request object
    func approveMFARequest(_ request: MFARequest) async throws {
        guard let vaultClient = vaultClient else {
            throw VaultAuthError.notConfigured
        }
        
        let handler = PushNotificationHandler(vaultClient: vaultClient)
        try await handler.approveMFARequest(requestId: request.requestId)
    }
    
    /// Deny MFA request with request object
    func denyMFARequest(_ request: MFARequest) async throws {
        guard let vaultClient = vaultClient else {
            throw VaultAuthError.notConfigured
        }
        
        let handler = PushNotificationHandler(vaultClient: vaultClient)
        try await handler.denyMFARequest(requestId: request.requestId)
    }
}

// MARK: - UNNotificationResponse Handling

#if canImport(UserNotifications)
import UserNotifications

@available(iOS 10.0, *)
public extension PushNotificationHandler {
    
    /// Handle a notification response (from notification action)
    static func handleNotificationResponse(
        _ response: UNNotificationResponse,
        vaultClient: VaultClient
    ) async {
        let userInfo = response.notification.request.content.userInfo
        let actionIdentifier = response.actionIdentifier
        
        guard let requestId = userInfo["request_id"] as? String else {
            return
        }
        
        let handler = PushNotificationHandler(vaultClient: vaultClient)
        
        do {
            switch actionIdentifier {
            case "APPROVE_MFA":
                try await handler.approveMFARequest(requestId: requestId)
                
            case "DENY_MFA":
                try await handler.denyMFARequest(requestId: requestId)
                
            default:
                break
            }
        } catch {
            print("Failed to handle notification action: \(error)")
        }
    }
}

// MARK: - Notification Categories

@available(iOS 10.0, *)
public extension UNNotificationCategory {
    
    /// Category for MFA push notifications
    static let mfaRequest = UNNotificationCategory(
        identifier: "MFA_REQUEST",
        actions: [
            UNNotificationAction(
                identifier: "APPROVE_MFA",
                title: "Approve",
                options: [.authenticationRequired]
            ),
            UNNotificationAction(
                identifier: "DENY_MFA",
                title: "Deny",
                options: [.destructive]
            )
        ],
        intentIdentifiers: [],
        options: []
    )
    
    /// Category for security alerts
    static let securityAlert = UNNotificationCategory(
        identifier: "SECURITY_ALERT",
        actions: [
            UNNotificationAction(
                identifier: "VIEW_ALERT",
                title: "View Details",
                options: [.foreground]
            ),
            UNNotificationAction(
                identifier: "ACKNOWLEDGE_ALERT",
                title: "Acknowledge",
                options: []
            )
        ],
        intentIdentifiers: [],
        options: []
    )
    
    /// All Vault notification categories
    static let vaultCategories: Set<UNNotificationCategory> = [
        mfaRequest,
        securityAlert
    ]
}
#endif
