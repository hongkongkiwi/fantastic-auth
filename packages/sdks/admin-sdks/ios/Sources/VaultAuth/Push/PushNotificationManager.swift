import Foundation
import UIKit

// MARK: - PushNotificationManager

public class PushNotificationManager: NSObject {
    
    // MARK: - Singleton
    
    public static let shared = PushNotificationManager()
    
    // MARK: - Properties
    
    private var vaultClient: VaultClient?
    private var deviceToken: Data?
    private var isRegistered = false
    private var pendingNotifications: [[AnyHashable: Any]] = []
    
    private let notificationCenter: NotificationCenter
    private let userDefaults: UserDefaults
    
    // MARK: - Public Properties
    
    public var onMFARequest: ((MFARequest) -> Void)?
    public var onPasswordReset: ((PasswordResetNotification) -> Void)?
    public var onSecurityAlert: ((SecurityAlert) -> Void)?
    public var onCustomNotification: ((CustomPushNotification) -> Void)?
    
    // MARK: - Initialization
    
    public init(
        notificationCenter: NotificationCenter = .default,
        userDefaults: UserDefaults = .standard
    ) {
        self.notificationCenter = notificationCenter
        self.userDefaults = userDefaults
        super.init()
    }
    
    // MARK: - Configuration
    
    func configure(with vaultClient: VaultClient) {
        self.vaultClient = vaultClient
    }
    
    // MARK: - Device Registration
    
    /// Register device for push notifications
    public func registerForRemoteNotifications() {
        DispatchQueue.main.async {
            UIApplication.shared.registerForRemoteNotifications()
        }
    }
    
    /// Register device token with Vault server
    /// - Parameter deviceToken: The device token received from Apple
    public func registerDevice(token deviceToken: Data) {
        self.deviceToken = deviceToken
        
        let tokenString = deviceToken.map { String(format: "%02.2hhx", $0) }.joined()
        userDefaults.set(tokenString, forKey: "vault_device_token")
        
        // Register with server if we have a client
        Task {
            await registerDeviceWithServer(token: tokenString)
        }
    }
    
    /// Unregister device from push notifications
    public func unregisterDevice() async {
        guard let token = userDefaults.string(forKey: "vault_device_token") else {
            return
        }
        
        do {
            try await vaultClient?.delete("/auth/devices", parameters: ["device_token": token])
            userDefaults.removeObject(forKey: "vault_device_token")
            isRegistered = false
        } catch {
            print("Failed to unregister device: \(error)")
        }
    }
    
    private func registerDeviceWithServer(token: String) async {
        guard let vaultClient = vaultClient else {
            return
        }
        
        let deviceInfo = DeviceInfo(
            token: token,
            platform: "ios",
            model: UIDevice.current.model,
            systemVersion: UIDevice.current.systemVersion,
            appVersion: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "unknown",
            deviceId: UIDevice.current.identifierForVendor?.uuidString ?? UUID().uuidString
        )
        
        do {
            try await vaultClient.post("/auth/devices", body: deviceInfo)
            isRegistered = true
        } catch {
            print("Failed to register device: \(error)")
        }
    }
    
    // MARK: - Notification Handling
    
    /// Handle incoming push notification
    /// - Parameters:
    ///   - userInfo: The notification payload
    ///   - completionHandler: The completion handler to call when done
    public func handleNotification(
        _ userInfo: [AnyHashable: Any],
        fetchCompletionHandler completionHandler: ((UIBackgroundFetchResult) -> Void)? = nil
    ) {
        // Store notification if not ready to process
        guard vaultClient != nil else {
            pendingNotifications.append(userInfo)
            completionHandler?(.noData)
            return
        }
        
        // Parse notification
        guard let type = userInfo["type"] as? String else {
            completionHandler?(.noData)
            return
        }
        
        switch type {
        case "mfa_request":
            handleMFARequest(userInfo)
            completionHandler?(.newData)
            
        case "mfa_approved":
            handleMFAApproved(userInfo)
            completionHandler?(.newData)
            
        case "mfa_denied":
            handleMFADenied(userInfo)
            completionHandler?(.newData)
            
        case "password_reset":
            handlePasswordReset(userInfo)
            completionHandler?(.newData)
            
        case "security_alert":
            handleSecurityAlert(userInfo)
            completionHandler?(.newData)
            
        case "session_revoked":
            handleSessionRevoked(userInfo)
            completionHandler?(.newData)
            
        default:
            handleCustomNotification(userInfo)
            completionHandler?(.newData)
        }
    }
    
    // MARK: - Private Handlers
    
    private func handleMFARequest(_ userInfo: [AnyHashable: Any]) {
        guard let request = MFARequest(from: userInfo) else {
            return
        }
        
        notificationCenter.post(name: .mfaRequestReceived, object: request)
        onMFARequest?(request)
    }
    
    private func handleMFAApproved(_ userInfo: [AnyHashable: Any]) {
        notificationCenter.post(name: .mfaRequestApproved, object: userInfo)
    }
    
    private func handleMFADenied(_ userInfo: [AnyHashable: Any]) {
        notificationCenter.post(name: .mfaRequestDenied, object: userInfo)
    }
    
    private func handlePasswordReset(_ userInfo: [AnyHashable: Any]) {
        guard let notification = PasswordResetNotification(from: userInfo) else {
            return
        }
        
        notificationCenter.post(name: .passwordResetReceived, object: notification)
        onPasswordReset?(notification)
    }
    
    private func handleSecurityAlert(_ userInfo: [AnyHashable: Any]) {
        guard let alert = SecurityAlert(from: userInfo) else {
            return
        }
        
        notificationCenter.post(name: .securityAlertReceived, object: alert)
        onSecurityAlert?(alert)
    }
    
    private func handleSessionRevoked(_ userInfo: [AnyHashable: Any]) {
        notificationCenter.post(name: .sessionRevoked, object: userInfo)
    }
    
    private func handleCustomNotification(_ userInfo: [AnyHashable: Any]) {
        let notification = CustomPushNotification(userInfo: userInfo)
        notificationCenter.post(name: .customNotificationReceived, object: notification)
        onCustomNotification?(notification)
    }
    
    // MARK: - Process Pending Notifications
    
    func processPendingNotifications() {
        let notifications = pendingNotifications
        pendingNotifications.removeAll()
        
        for notification in notifications {
            handleNotification(notification)
        }
    }
}

// MARK: - Notification Types

public struct MFARequest {
    public let requestId: String
    public let deviceName: String
    public let deviceLocation: String?
    public let ipAddress: String?
    public let timestamp: Date
    public let action: String
    
    init?(from userInfo: [AnyHashable: Any]) {
        guard let requestId = userInfo["request_id"] as? String,
              let deviceName = userInfo["device_name"] as? String else {
            return nil
        }
        
        self.requestId = requestId
        self.deviceName = deviceName
        self.deviceLocation = userInfo["device_location"] as? String
        self.ipAddress = userInfo["ip_address"] as? String
        self.timestamp = (userInfo["timestamp"] as? TimeInterval).map { Date(timeIntervalSince1970: $0) } ?? Date()
        self.action = userInfo["action"] as? String ?? "login"
    }
}

public struct PasswordResetNotification {
    public let token: String
    public let email: String
    public let expiresAt: Date
    
    init?(from userInfo: [AnyHashable: Any]) {
        guard let token = userInfo["reset_token"] as? String,
              let email = userInfo["email"] as? String else {
            return nil
        }
        
        self.token = token
        self.email = email
        self.expiresAt = (userInfo["expires_at"] as? TimeInterval).map { Date(timeIntervalSince1970: $0) } ?? Date()
    }
}

public struct SecurityAlert {
    public let alertType: String
    public let message: String
    public let severity: String
    public let timestamp: Date
    
    init?(from userInfo: [AnyHashable: Any]) {
        guard let alertType = userInfo["alert_type"] as? String,
              let message = userInfo["message"] as? String else {
            return nil
        }
        
        self.alertType = alertType
        self.message = message
        self.severity = userInfo["severity"] as? String ?? "low"
        self.timestamp = (userInfo["timestamp"] as? TimeInterval).map { Date(timeIntervalSince1970: $0) } ?? Date()
    }
}

public struct CustomPushNotification {
    public let userInfo: [AnyHashable: Any]
    public let type: String?
    
    init(userInfo: [AnyHashable: Any]) {
        self.userInfo = userInfo
        self.type = userInfo["type"] as? String
    }
}

// MARK: - Device Info

struct DeviceInfo: Codable {
    let token: String
    let platform: String
    let model: String
    let systemVersion: String
    let appVersion: String
    let deviceId: String
}

// MARK: - Notification Names

public extension Notification.Name {
    static let mfaRequestReceived = Notification.Name("VaultMFARequestReceived")
    static let mfaRequestApproved = Notification.Name("VaultMFARequestApproved")
    static let mfaRequestDenied = Notification.Name("VaultMFARequestDenied")
    static let passwordResetReceived = Notification.Name("VaultPasswordResetReceived")
    static let securityAlertReceived = Notification.Name("VaultSecurityAlertReceived")
    static let sessionRevoked = Notification.Name("VaultSessionRevoked")
    static let customNotificationReceived = Notification.Name("VaultCustomNotificationReceived")
}
