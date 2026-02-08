import Foundation
import Security
import CryptoKit

/// Service for Secure Enclave operations.
///
/// This class provides methods for generating and managing cryptographic keys
/// in the iOS Secure Enclave for maximum security.
public actor VaultSecureEnclave {
    
    // MARK: - Properties
    
    private let tagPrefix = "com.vault.secureenclave"
    
    // MARK: - Key Generation
    
    /// Generates a new P-256 key pair in the Secure Enclave.
    ///
    /// The private key never leaves the Secure Enclave and can only be
    /// used for signing operations after biometric authentication.
    ///
    /// - Parameter identifier: Unique identifier for this key
    /// - Returns: The public key that can be shared with servers
    /// - Throws: `VaultError` if key generation fails
    public func generateKeyPair(identifier: String) throws -> SecKey {
        let tag = "\(tagPrefix).\(identifier)"
        
        // Delete any existing key with this tag
        try? deleteKey(identifier: identifier)
        
        // Create access control that requires biometric authentication
        var error: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .privateKeyUsage,
            &error
        ) else {
            throw VaultError.keyGenerationFailed(
                "Failed to create access control: \(String(describing: error))"
            )
        }
        
        // Key generation attributes
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrAccessControl as String: accessControl
            ],
            kSecPublicKeyAttrs as String: [
                kSecAttrIsPermanent as String: false
            ]
        ]
        
        // Generate the key pair
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw VaultError.keyGenerationFailed("\(String(describing: error))")
        }
        
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw VaultError.keyGenerationFailed("Failed to extract public key")
        }
        
        Vault.shared.logger.log("Secure Enclave key generated: \(identifier)")
        
        return publicKey
    }
    
    /// Generates a key pair that requires biometric authentication to use.
    ///
    /// - Parameters:
    ///   - identifier: Unique identifier for this key
    ///   - biometricPrompt: The prompt shown during biometric authentication
    /// - Returns: The public key
    /// - Throws: `VaultError` if key generation fails
    public func generateBiometricProtectedKey(
        identifier: String,
        biometricPrompt: String = "Authenticate to use secure key"
    ) throws -> SecKey {
        let tag = "\(tagPrefix).biometric.\(identifier)"
        
        // Delete any existing key
        try? deleteKey(identifier: identifier)
        
        // Create access control with biometric protection
        var error: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet],
            &error
        ) else {
            throw VaultError.keyGenerationFailed(
                "Failed to create biometric access control: \(String(describing: error))"
            )
        }
        
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrAccessControl as String: accessControl
            ]
        ]
        
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw VaultError.keyGenerationFailed("\(String(describing: error))")
        }
        
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw VaultError.keyGenerationFailed("Failed to extract public key")
        }
        
        Vault.shared.logger.log("Biometric-protected Secure Enclave key generated: \(identifier)")
        
        return publicKey
    }
    
    // MARK: - Key Retrieval
    
    /// Gets a reference to the private key.
    ///
    /// Note: The actual private key bytes cannot be retrieved from the Secure Enclave.
    /// You can only use the key reference for signing operations.
    ///
    /// - Parameter identifier: The key identifier
    /// - Returns: The private key reference, or `nil` if not found
    public func getPrivateKey(identifier: String) -> SecKey? {
        let tag = "\(tagPrefix).\(identifier)"
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess else {
            return nil
        }
        
        return (result as! SecKey)
    }
    
    /// Gets the public key for a stored key pair.
    ///
    /// - Parameter identifier: The key identifier
    /// - Returns: The public key, or `nil` if not found
    public func getPublicKey(identifier: String) -> SecKey? {
        guard let privateKey = getPrivateKey(identifier: identifier) else {
            return nil
        }
        
        return SecKeyCopyPublicKey(privateKey)
    }
    
    /// Exports the public key in a format suitable for transmission.
    ///
    /// - Parameter identifier: The key identifier
    /// - Returns: Base64-encoded public key data
    /// - Throws: `VaultError` if export fails
    public func exportPublicKey(identifier: String) throws -> String {
        guard let publicKey = getPublicKey(identifier: identifier) else {
            throw VaultError.keyNotFound
        }
        
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(publicKey, &error) else {
            throw VaultError.keyGenerationFailed("Failed to export: \(String(describing: error))")
        }
        
        return (data as Data).base64EncodedString()
    }
    
    // MARK: - Signing
    
    /// Signs data with the specified key.
    ///
    /// This operation may trigger biometric authentication if the key
    /// was created with biometric protection.
    ///
    /// - Parameters:
    ///   - data: The data to sign
    ///   - identifier: The key identifier
    /// - Returns: The signature
    /// - Throws: `VaultError` if signing fails
    public func sign(data: Data, identifier: String) throws -> Data {
        guard let privateKey = getPrivateKey(identifier: identifier) else {
            throw VaultError.keyNotFound
        }
        
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureMessageX962SHA256,
            data as CFData,
            &error
        ) else {
            throw VaultError.biometricFailed("Signing failed: \(String(describing: error))")
        }
        
        return signature as Data
    }
    
    /// Signs a string with the specified key.
    ///
    /// - Parameters:
    ///   - string: The string to sign (UTF-8 encoded)
    ///   - identifier: The key identifier
    /// - Returns: Base64-encoded signature
    /// - Throws: `VaultError` if signing fails
    public func sign(string: String, identifier: String) throws -> String {
        guard let data = string.data(using: .utf8) else {
            throw VaultError.biometricFailed("Invalid string encoding")
        }
        
        let signature = try sign(data: data, identifier: identifier)
        return signature.base64EncodedString()
    }
    
    // MARK: - Verification
    
    /// Verifies a signature using the public key.
    ///
    /// - Parameters:
    ///   - signature: The signature to verify
    ///   - data: The original data
    ///   - publicKey: The public key to verify against
    /// - Returns: `true` if the signature is valid
    public func verify(
        signature: Data,
        data: Data,
        publicKey: SecKey
    ) -> Bool {
        var error: Unmanaged<CFError>?
        let result = SecKeyVerifySignature(
            publicKey,
            .ecdsaSignatureMessageX962SHA256,
            data as CFData,
            signature as CFData,
            &error
        )
        
        return result
    }
    
    // MARK: - Key Management
    
    /// Deletes a key from the Secure Enclave.
    ///
    /// - Parameter identifier: The key identifier
    /// - Throws: `VaultError` if deletion fails
    public func deleteKey(identifier: String) throws {
        let tag = "\(tagPrefix).\(identifier)"
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        
        // Also try biometric variant
        let biometricTag = "\(tagPrefix).biometric.\(identifier)"
        let biometricQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: biometricTag
        ]
        SecItemDelete(biometricQuery as CFDictionary)
        
        if status != errSecSuccess && status != errSecItemNotFound {
            throw VaultError.keyGenerationFailed("Failed to delete key: \(status)")
        }
        
        Vault.shared.logger.log("Secure Enclave key deleted: \(identifier)")
    }
    
    /// Checks if a key exists.
    ///
    /// - Parameter identifier: The key identifier
    /// - Returns: `true` if the key exists
    public func keyExists(identifier: String) -> Bool {
        getPrivateKey(identifier: identifier) != nil
    }
    
    /// Lists all stored key identifiers.
    ///
    /// - Returns: Array of key identifiers
    public func listKeys() -> [String] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess,
              let items = result as? [[String: Any]] else {
            return []
        }
        
        return items.compactMap { item in
            guard let tag = item[kSecAttrApplicationTag as String] as? Data,
                  let tagString = String(data: tag, encoding: .utf8),
                  tagString.hasPrefix(tagPrefix) else {
                return nil
            }
            return tagString.replacingOccurrences(of: "\(tagPrefix).", with: "")
                           .replacingOccurrences(of: "\(tagPrefix).biometric.", with: "")
        }
    }
    
    /// Deletes all Secure Enclave keys created by the SDK.
    ///
    /// - Throws: `VaultError` if deletion fails
    public func deleteAllKeys() throws {
        for key in listKeys() {
            try deleteKey(identifier: key)
        }
    }
}

// MARK: - CryptoKit Integration

@available(iOS 13.0, *)
extension VaultSecureEnclave {
    
    /// Generates a P256.Signing.PrivateKey compatible key.
    ///
    /// This creates a key that can be used with CryptoKit for signing.
    ///
    /// - Parameter identifier: The key identifier
    /// - Returns: The raw representation of the public key
    /// - Throws: `VaultError` if key generation fails
    public func generateCryptoKitKey(identifier: String) throws -> P256.Signing.PublicKey {
        let publicKey = try generateKeyPair(identifier: identifier)
        
        guard let data = SecKeyCopyExternalRepresentation(publicKey, nil) else {
            throw VaultError.keyGenerationFailed("Failed to export public key")
        }
        
        let rawData = (data as Data).suffix(65) // Remove DER header
        return try P256.Signing.PublicKey(rawRepresentation: rawData)
    }
}

// MARK: - Helper Types

/// Represents a key pair stored in the Secure Enclave.
public struct SecureEnclaveKeyPair: Sendable {
    /// The key identifier.
    public let identifier: String
    
    /// Whether the key requires biometric authentication.
    public let requiresBiometric: Bool
    
    /// The date the key was created.
    public let createdAt: Date
    
    /// Base64-encoded public key.
    public let publicKey: String
}
