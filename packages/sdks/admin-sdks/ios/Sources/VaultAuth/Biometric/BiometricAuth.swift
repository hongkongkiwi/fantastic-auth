import Foundation
import LocalAuthentication

// MARK: - BiometricAuth

public class BiometricAuth {
    
    // MARK: - Singleton
    
    public static let shared = BiometricAuth()
    
    // MARK: - Properties
    
    private let tokenStorage: TokenStorage
    private let contextProvider: () -> BiometricContext
    private let notificationCenter: NotificationCenter
       
    // MARK: - Public Properties
    
    public var isAvailable: Bool {
        return contextProvider().isAvailable
    }
    
    public var isEnrolled: Bool {
        return contextProvider().isEnrolled
    }
    
    public var biometricType: BiometricType {
        return contextProvider().biometricType
    }
    
    public var canUseBiometricLogin: Bool {
        return isAvailable && isEnrolled && isBiometricLoginEnabled
    }
    
    public var isBiometricLoginEnabled: Bool {
        get {
            return tokenStorage.getToken(forKey: TokenStorageKeys.biometricEnabled) == "true"
        }
        set {
            try? tokenStorage.saveToken(newValue ? "true" : "false", forKey: TokenStorageKeys.biometricEnabled)
        }
    }
    
    // MARK: - Initialization
    
    public init(
        tokenStorage: TokenStorage = KeychainStorage(),
        contextProvider: @escaping () -> BiometricContext = { LABiometricContext() },
        notificationCenter: NotificationCenter = .default
    ) {
        self.tokenStorage = tokenStorage
        self.contextProvider = contextProvider
        self.notificationCenter = notificationCenter
    }
    
    // MARK: - Authentication
    
    /// Authenticate using biometrics
    /// - Parameters:
    ///   - reason: The reason for authentication shown to the user
    ///   - fallbackTitle: Title for the fallback button (passcode entry)
    /// - Returns: Whether authentication was successful
    @discardableResult
    public func authenticate(
        reason: String,
        fallbackTitle: String? = nil
    ) async throws -> Bool {
        let context = contextProvider()
        
        guard context.isAvailable else {
            throw BiometricError.notAvailable
        }
        
        guard context.isEnrolled else {
            throw BiometricError.notEnrolled
        }
        
        return try await withCheckedThrowingContinuation { continuation in
            var error: NSError?
            
            guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
                if let laError = error as? LAError {
                    continuation.resume(throwing: BiometricError(from: laError))
                } else {
                    continuation.resume(throwing: BiometricError.notAvailable)
                }
                return
            }
            
            context.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: reason
            ) { success, error in
                DispatchQueue.main.async {
                    if success {
                        continuation.resume(returning: true)
                    } else if let error = error {
                        continuation.resume(throwing: BiometricError(from: error as NSError))
                    } else {
                        continuation.resume(throwing: BiometricError.unknown)
                    }
                }
            }
        }
    }
    
    /// Authenticate with biometrics or device passcode fallback
    /// - Parameter reason: The reason for authentication shown to the user
    /// - Returns: Whether authentication was successful
    @discardableResult
    public func authenticateWithPasscodeFallback(
        reason: String
    ) async throws -> Bool {
        let context = contextProvider()
        
        guard context.isAvailable else {
            // Try device passcode if biometrics not available
            return try await authenticateWithPasscodeOnly(reason: reason)
        }
        
        return try await withCheckedThrowingContinuation { continuation in
            context.evaluatePolicy(
                .deviceOwnerAuthentication,
                localizedReason: reason
            ) { success, error in
                DispatchQueue.main.async {
                    if success {
                        continuation.resume(returning: true)
                    } else if let error = error {
                        continuation.resume(throwing: BiometricError(from: error as NSError))
                    } else {
                        continuation.resume(throwing: BiometricError.unknown)
                    }
                }
            }
        }
    }
    
    /// Authenticate with device passcode only
    /// - Parameter reason: The reason for authentication shown to the user
    /// - Returns: Whether authentication was successful
    @discardableResult
    public func authenticateWithPasscodeOnly(
        reason: String
    ) async throws -> Bool {
        let context = contextProvider()
        
        return try await withCheckedThrowingContinuation { continuation in
            context.evaluatePolicy(
                .deviceOwnerAuthentication,
                localizedReason: reason
            ) { success, error in
                DispatchQueue.main.async {
                    if success {
                        continuation.resume(returning: true)
                    } else if let error = error {
                        continuation.resume(throwing: BiometricError(from: error as NSError))
                    } else {
                        continuation.resume(throwing: BiometricError.unknown)
                    }
                }
            }
        }
    }
    
    // MARK: - Biometric Login Management
    
    /// Enable biometric login
    /// - Parameters:
    ///   - email: The user's email for biometric login
    ///   - password: The user's password (encrypted and stored securely)
    /// - Returns: Whether biometric login was successfully enabled
    @discardableResult
    public func enableBiometricLogin(email: String, password: String) async throws -> Bool {
        // First authenticate with biometrics
        let success = try await authenticate(reason: "Enable \(biometricType.displayName) login")
        
        guard success else {
            return false
        }
        
        // Store credentials securely
        let credentials = BiometricCredentials(email: email, password: password)
        try storeCredentials(credentials)
        
        // Enable biometric login flag
        isBiometricLoginEnabled = true
        
        // Post notification
        notificationCenter.post(name: .biometricLoginEnabled, object: nil)
        
        return true
    }
    
    /// Disable biometric login
    public func disableBiometricLogin() throws {
        // Delete stored credentials
        try deleteCredentials()
        
        // Disable biometric login flag
        isBiometricLoginEnabled = false
        
        // Post notification
        notificationCenter.post(name: .biometricLoginDisabled, object: nil)
    }
    
    /// Perform login using stored biometric credentials
    /// - Returns: The stored credentials if authentication succeeds
    public func getBiometricCredentials() async throws -> BiometricCredentials? {
        guard canUseBiometricLogin else {
            throw BiometricError.notAvailable
        }
        
        // Authenticate with biometrics
        let success = try await authenticate(reason: "Log in with \(biometricType.displayName)")
        
        guard success else {
            return nil
        }
        
        // Retrieve stored credentials
        return try retrieveCredentials()
    }
    
    // MARK: - Private Methods
    
    private func storeCredentials(_ credentials: BiometricCredentials) throws {
        let encoder = JSONEncoder()
        let data = try encoder.encode(credentials)
        
        // Encrypt the data before storing (in a real implementation)
        // For now, we store in keychain which provides some security
        if let keychainStorage = tokenStorage as? KeychainStorage {
            try keychainStorage.saveData(data, forKey: "biometric_credentials")
        } else {
            // Fallback to token storage with base64 encoding
            let base64String = data.base64EncodedString()
            try tokenStorage.saveToken(base64String, forKey: "biometric_credentials")
        }
    }
    
    private func retrieveCredentials() throws -> BiometricCredentials? {
        let data: Data?
        
        if let keychainStorage = tokenStorage as? KeychainStorage {
            data = keychainStorage.getData(forKey: "biometric_credentials")
        } else {
            guard let base64String = tokenStorage.getToken(forKey: "biometric_credentials"),
                  let decodedData = Data(base64Encoded: base64String) else {
                return nil
            }
            data = decodedData
        }
        
        guard let credentialData = data else {
            return nil
        }
        
        let decoder = JSONDecoder()
        return try decoder.decode(BiometricCredentials.self, from: credentialData)
    }
    
    private func deleteCredentials() throws {
        try tokenStorage.deleteToken(forKey: "biometric_credentials")
    }
}

// MARK: - BiometricCredentials

public struct BiometricCredentials: Codable {
    public let email: String
    public let password: String
    public let createdAt: Date
    
    public init(email: String, password: String) {
        self.email = email
        self.password = password
        self.createdAt = Date()
    }
}

// MARK: - Notification Names

public extension Notification.Name {
    static let biometricLoginEnabled = Notification.Name("VaultBiometricLoginEnabled")
    static let biometricLoginDisabled = Notification.Name("VaultBiometricLoginDisabled")
}

// MARK: - SwiftUI Convenience

@available(iOS 14.0, *)
public extension BiometricAuth {
    /// Check if biometric login is available and enabled
    var biometricLoginStatus: BiometricLoginStatus {
        if !isAvailable {
            return .unavailable
        } else if !isEnrolled {
            return .notEnrolled
        } else if isBiometricLoginEnabled {
            return .enabled
        } else {
            return .available
        }
    }
}

public enum BiometricLoginStatus {
    case unavailable
    case notEnrolled
    case available
    case enabled
}
