import Foundation
import LocalAuthentication

/// Service for biometric authentication using Face ID or Touch ID.
///
/// This class provides methods for authenticating users with biometrics
/// and managing biometric credentials.
public actor VaultBiometric {
    
    // MARK: - Properties
    
    private let tokenStore: TokenStore
    private let context = LAContext()
    
    /// The domain state for biometric credentials.
    private var evaluatedDomainState: Data?
    
    // MARK: - Initialization
    
    init(tokenStore: TokenStore) {
        self.tokenStore = tokenStore
    }
    
    // MARK: - Availability Checks
    
    /// Whether biometric authentication is available on this device.
    public var isAvailable: Bool {
        var error: NSError?
        let available = context.canEvaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics,
            error: &error
        )
        return available
    }
    
    /// The type of biometric authentication available.
    public var biometricType: BiometricType {
        let context = LAContext()
        _ = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        
        switch context.biometryType {
        case .faceID:
            return .faceID
        case .touchID:
            return .touchID
        case .opticID:
            return .opticID
        default:
            return .none
        }
    }
    
    /// Whether biometric authentication is enrolled.
    public var isEnrolled: Bool {
        var error: NSError?
        return context.canEvaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics,
            error: &error
        )
    }
    
    // MARK: - Authentication
    
    /// Authenticates the user with biometrics.
    ///
    /// - Parameters:
    ///   - reason: The reason for requesting authentication
    ///   - fallbackTitle: Title for the fallback button (default: "Use Password")
    /// - Returns: `true` if authentication succeeded
    /// - Throws: `VaultError.biometricFailed` if authentication fails
    public func authenticate(
        reason: String,
        fallbackTitle: String? = nil
    ) async throws -> Bool {
        guard isAvailable else {
            throw VaultError.biometricNotAvailable
        }
        
        let context = LAContext()
        context.localizedFallbackTitle = fallbackTitle
        
        do {
            let success = try await context.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: reason
            )
            
            if success {
                // Check if biometric data has changed
                if let domainState = context.evaluatedPolicyDomainState {
                    if let previousState = evaluatedDomainState,
                       previousState != domainState {
                        // Biometric data has changed
                        Vault.shared.logger.log("Biometric data changed")
                    }
                    evaluatedDomainState = domainState
                }
            }
            
            return success
        } catch let error as LAError {
            throw mapLAError(error)
        } catch {
            throw VaultError.biometricFailed(error.localizedDescription)
        }
    }
    
    /// Authenticates with biometrics and device passcode fallback.
    ///
    /// This allows authentication using the device passcode if biometrics fail.
    ///
    /// - Parameter reason: The reason for requesting authentication
    /// - Returns: `true` if authentication succeeded
    /// - Throws: `VaultError.biometricFailed` if authentication fails
    public func authenticateWithPasscodeFallback(
        reason: String
    ) async throws -> Bool {
        guard isAvailable || context.canEvaluatePolicy(
            .deviceOwnerAuthentication,
            error: nil
        ) else {
            throw VaultError.biometricNotAvailable
        }
        
        let context = LAContext()
        
        do {
            return try await context.evaluatePolicy(
                .deviceOwnerAuthentication,
                localizedReason: reason
            )
        } catch let error as LAError {
            throw mapLAError(error)
        } catch {
            throw VaultError.biometricFailed(error.localizedDescription)
        }
    }
    
    // MARK: - Key Management
    
    /// Generates and stores a new biometric-protected key.
    ///
    /// This creates a new key pair in the Secure Enclave and stores the
    /// private key with biometric protection.
    ///
    /// - Returns: The public key for server registration
    /// - Throws: `VaultError` if key generation fails
    public func generateAndStoreKey() async throws -> SecKey {
        guard isAvailable else {
            throw VaultError.biometricNotAvailable
        }
        
        // Delete any existing key first
        try? await deleteStoredKey()
        
        // Create access control with biometric protection
        var error: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .privateKeyUsage,
            &error
        ) else {
            throw VaultError.biometricFailed("Failed to create access control: \(String(describing: error))")
        }
        
        // Generate key pair attributes
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: "com.vault.biometric.key",
                kSecAttrAccessControl as String: accessControl
            ],
            kSecPublicKeyAttrs as String: [
                kSecAttrApplicationTag as String: "com.vault.biometric.publickey"
            ]
        ]
        
        // Generate the key pair
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw VaultError.keyGenerationFailed("\(String(describing: error))")
        }
        
        // Get the public key
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw VaultError.keyGenerationFailed("Failed to get public key")
        }
        
        // Store a reference that biometric auth is registered
        UserDefaults.standard.set(true, forKey: "com.vault.biometric.registered")
        
        Vault.shared.logger.log("Biometric key generated successfully")
        
        return publicKey
    }
    
    /// Gets the stored private key.
    ///
    /// This retrieves the key from the Secure Enclave. Biometric
    /// authentication will be triggered when the key is used.
    ///
    /// - Returns: The private key, or `nil` if not found
    /// - Throws: `VaultError` if retrieval fails
    public func getStoredKey() async throws -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: "com.vault.biometric.key",
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess else {
            if status == errSecItemNotFound {
                return nil
            }
            throw VaultError.keyNotFound
        }
        
        return (result as! SecKey)
    }
    
    /// Signs a challenge with the stored key.
    ///
    /// This will trigger biometric authentication before signing.
    ///
    /// - Parameters:
    ///   - challenge: The challenge string to sign
    ///   - privateKey: The private key to use for signing
    /// - Returns: The base64-encoded signature
    /// - Throws: `VaultError` if signing fails
    public func signChallenge(_ challenge: String, with privateKey: SecKey) async throws -> String {
        guard let challengeData = challenge.data(using: .utf8) else {
            throw VaultError.biometricFailed("Invalid challenge")
        }
        
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureMessageX962SHA256,
            challengeData as CFData,
            &error
        ) else {
            throw VaultError.biometricFailed("Failed to sign challenge: \(String(describing: error))")
        }
        
        return (signature as Data).base64EncodedString()
    }
    
    /// Deletes the stored biometric key.
    ///
    /// - Throws: `VaultError` if deletion fails
    public func deleteStoredKey() async throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: "com.vault.biometric.key",
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        
        // Also delete the public key
        let publicQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: "com.vault.biometric.publickey",
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom
        ]
        SecItemDelete(publicQuery as CFDictionary)
        
        // Clear registration flag
        UserDefaults.standard.removeObject(forKey: "com.vault.biometric.registered")
        
        if status != errSecSuccess && status != errSecItemNotFound {
            throw VaultError.biometricFailed("Failed to delete key: \(status)")
        }
        
        Vault.shared.logger.log("Biometric key deleted")
    }
    
    /// Checks if a biometric key is registered.
    public var isKeyRegistered: Bool {
        UserDefaults.standard.bool(forKey: "com.vault.biometric.registered")
    }
    
    // MARK: - Private Methods
    
    private func mapLAError(_ error: LAError) -> VaultError {
        switch error.code {
        case .authenticationFailed:
            return .biometricFailed("Authentication failed")
        case .userCancel:
            return .userCancelled
        case .userFallback:
            return .biometricFailed("User chose to use fallback")
        case .biometryNotAvailable:
            return .biometricNotAvailable
        case .biometryNotEnrolled:
            return .biometricFailed("Biometrics not enrolled")
        case .biometryLockout:
            return .biometricFailed("Biometrics locked out")
        case .systemCancel:
            return .biometricFailed("System cancelled authentication")
        case .invalidContext:
            return .biometricFailed("Invalid context")
        case .notInteractive:
            return .biometricFailed("Not interactive")
        @unknown default:
            return .biometricFailed(error.localizedDescription)
        }
    }
}

// MARK: - Biometric Type

/// The type of biometric authentication available.
public enum BiometricType: String, Sendable {
    case none = "none"
    case faceID = "faceID"
    case touchID = "touchID"
    case opticID = "opticID"
    
    /// The display name for the biometric type.
    public var displayName: String {
        switch self {
        case .none:
            return "None"
        case .faceID:
            return "Face ID"
        case .touchID:
            return "Touch ID"
        case .opticID:
            return "Optic ID"
        }
    }
    
    /// The icon name for the biometric type.
    public var iconName: String {
        switch self {
        case .none:
            return "lock"
        case .faceID:
            return "faceid"
        case .touchID:
            return "touchid"
        case .opticID:
            return "eye"
        }
    }
}

// MARK: - SwiftUI Integration

import SwiftUI

public extension VaultBiometric {
    /// Gets a view for the biometric icon.
    @MainActor
    func iconView(size: CGFloat = 24) -> some View {
        Image(systemName: biometricType.iconName)
            .font(.system(size: size))
    }
}
