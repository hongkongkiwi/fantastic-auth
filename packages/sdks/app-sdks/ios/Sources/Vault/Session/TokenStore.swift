import Foundation
import Security

/// Secure storage for authentication tokens using the iOS Keychain.
///
/// This class provides a secure way to store and retrieve authentication
/// tokens using the iOS Keychain Services.
internal actor TokenStore {
    
    // MARK: - Properties
    
    /// Key for the access token in the keychain.
    private let accessTokenKey = "com.vault.access_token"
    
    /// Key for the refresh token in the keychain.
    private let refreshTokenKey = "com.vault.refresh_token"
    
    /// Key for storing the token expiration date.
    private let tokenExpiresKey = "com.vault.token_expires"
    
    /// Key for the user's ID.
    private let userIdKey = "com.vault.user_id"
    
    /// The service name for keychain items.
    private let serviceName = "com.vault.sdk"
    
    /// In-memory cache for the access token to avoid keychain lookups.
    private var cachedAccessToken: String?
    
    /// In-memory cache for the refresh token.
    private var cachedRefreshToken: String?
    
    // MARK: - Token Management
    
    /// Stores both access and refresh tokens.
    ///
    /// - Parameters:
    ///   - accessToken: The access token
    ///   - refreshToken: The refresh token
    func setTokens(accessToken: String, refreshToken: String) {
        // Store in keychain
        saveToKeychain(key: accessTokenKey, value: accessToken)
        saveToKeychain(key: refreshTokenKey, value: refreshToken)
        
        // Cache in memory
        cachedAccessToken = accessToken
        cachedRefreshToken = refreshToken
        
        // Store expiration (default 1 hour)
        let expiresAt = Date().addingTimeInterval(3600)
        UserDefaults.standard.set(expiresAt, forKey: tokenExpiresKey)
        
        Vault.shared.logger.log("Tokens stored successfully")
    }
    
    /// Gets the access token.
    ///
    /// - Returns: The access token, or `nil` if not found
    func getAccessToken() -> String? {
        // Check cache first
        if let cached = cachedAccessToken {
            return cached
        }
        
        // Fetch from keychain
        if let token = loadFromKeychain(key: accessTokenKey) {
            cachedAccessToken = token
            return token
        }
        
        return nil
    }
    
    /// Gets the refresh token.
    ///
    /// - Returns: The refresh token, or `nil` if not found
    func getRefreshToken() -> String? {
        // Check cache first
        if let cached = cachedRefreshToken {
            return cached
        }
        
        // Fetch from keychain
        if let token = loadFromKeychain(key: refreshTokenKey) {
            cachedRefreshToken = token
            return token
        }
        
        return nil
    }
    
    /// Updates just the access token (used during token refresh).
    ///
    /// - Parameter accessToken: The new access token
    func updateAccessToken(_ accessToken: String) {
        saveToKeychain(key: accessTokenKey, value: accessToken)
        cachedAccessToken = accessToken
        
        // Update expiration
        let expiresAt = Date().addingTimeInterval(3600)
        UserDefaults.standard.set(expiresAt, forKey: tokenExpiresKey)
    }
    
    /// Clears all stored tokens.
    func clearTokens() {
        deleteFromKeychain(key: accessTokenKey)
        deleteFromKeychain(key: refreshTokenKey)
        
        cachedAccessToken = nil
        cachedRefreshToken = nil
        
        UserDefaults.standard.removeObject(forKey: tokenExpiresKey)
        UserDefaults.standard.removeObject(forKey: userIdKey)
        
        Vault.shared.logger.log("Tokens cleared")
    }
    
    /// Checks if the access token is expired.
    ///
    /// - Returns: `true` if the token is expired or doesn't exist
    func isTokenExpired() -> Bool {
        guard let expiresAt = UserDefaults.standard.object(forKey: tokenExpiresKey) as? Date else {
            return true
        }
        
        // Consider token expired 5 minutes before actual expiration
        let earlyExpiration = expiresAt.addingTimeInterval(-300)
        return Date() >= earlyExpiration
    }
    
    /// Stores the user ID.
    ///
    /// - Parameter userId: The user's ID
    func setUserId(_ userId: String) {
        UserDefaults.standard.set(userId, forKey: userIdKey)
    }
    
    /// Gets the stored user ID.
    ///
    /// - Returns: The user ID, or `nil` if not found
    func getUserId() -> String? {
        UserDefaults.standard.string(forKey: userIdKey)
    }
    
    // MARK: - Keychain Operations
    
    /// Saves a value to the keychain.
    ///
    /// - Parameters:
    ///   - key: The key for the item
    ///   - value: The value to store
    private func saveToKeychain(key: String, value: String) {
        guard let data = value.data(using: .utf8) else { return }
        
        // Delete any existing item first
        deleteFromKeychain(key: key)
        
        // Create query
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        
        let status = SecItemAdd(query as CFDictionary, nil)
        
        if status != errSecSuccess {
            Vault.shared.logger.logError("Failed to save to keychain: \(status)")
        }
    }
    
    /// Loads a value from the keychain.
    ///
    /// - Parameter key: The key for the item
    /// - Returns: The stored value, or `nil` if not found
    private func loadFromKeychain(key: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess,
              let data = result as? Data,
              let value = String(data: data, encoding: .utf8) else {
            return nil
        }
        
        return value
    }
    
    /// Deletes a value from the keychain.
    ///
    /// - Parameter key: The key for the item
    private func deleteFromKeychain(key: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: key
        ]
        
        SecItemDelete(query as CFDictionary)
    }
    
    // MARK: - Debug Helpers
    
    /// Checks if tokens exist (for debugging purposes).
    ///
    /// - Returns: `true` if tokens exist in the keychain
    func hasTokens() -> Bool {
        loadFromKeychain(key: accessTokenKey) != nil
    }
}

// MARK: - Keychain Access Group Support

#if canImport(LocalAuthentication)
import LocalAuthentication

extension TokenStore {
    
    /// Saves a value to the keychain with biometric protection.
    ///
    /// - Parameters:
    ///   - key: The key for the item
    ///   - value: The value to store
    ///   - biometricRequired: Whether biometric authentication is required
    func saveToKeychain(key: String, value: String, biometricRequired: Bool) {
        guard let data = value.data(using: .utf8) else { return }
        
        // Delete any existing item first
        deleteFromKeychain(key: key)
        
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: key,
            kSecValueData as String: data
        ]
        
        if biometricRequired {
            var error: Unmanaged<CFError>?
            guard let accessControl = SecAccessControlCreateWithFlags(
                nil,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                .biometryCurrentSet,
                &error
            ) else {
                Vault.shared.logger.logError("Failed to create access control: \(String(describing: error))")
                // Fall back to standard storage
                query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
                SecItemAdd(query as CFDictionary, nil)
                return
            }
            
            query[kSecAttrAccessControl as String] = accessControl
        } else {
            query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        }
        
        let status = SecItemAdd(query as CFDictionary, nil)
        
        if status != errSecSuccess {
            Vault.shared.logger.logError("Failed to save to keychain: \(status)")
        }
    }
}
#endif
