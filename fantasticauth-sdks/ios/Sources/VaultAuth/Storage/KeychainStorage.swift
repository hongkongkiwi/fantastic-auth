import Foundation
import Security

// MARK: - KeychainStorage

public class KeychainStorage: TokenStorage {
    private let service: String
    private let accessGroup: String?
    private let accessibility: CFString
    
    /// Initialize KeychainStorage
    /// - Parameters:
    ///   - service: The service identifier for keychain items (defaults to bundle identifier)
    ///   - accessGroup: The access group for shared keychain access
    ///   - accessibility: The accessibility level for keychain items
    public init(
        service: String? = nil,
        accessGroup: String? = nil,
        accessibility: CFString = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    ) {
        self.service = service ?? Bundle.main.bundleIdentifier ?? "com.vault.auth"
        self.accessGroup = accessGroup
        self.accessibility = accessibility
    }
    
    // MARK: - TokenStorage Implementation
    
    public func saveToken(_ token: String, forKey key: String) throws {
        guard let data = token.data(using: .utf8) else {
            throw KeychainError.conversionFailed
        }
        
        // Delete existing item first to avoid duplicates
        try? deleteToken(forKey: key)
        
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            kSecAttrAccessible as String: accessibility
        ]
        
        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        
        let status = SecItemAdd(query as CFDictionary, nil)
        
        guard status == errSecSuccess else {
            throw KeychainError.invalidStatus(status)
        }
    }
    
    public func getToken(forKey key: String) -> String? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess,
              let data = result as? Data,
              let token = String(data: data, encoding: .utf8) else {
            return nil
        }
        
        return token
    }
    
    public func deleteToken(forKey key: String) throws {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key
        ]
        
        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        
        let status = SecItemDelete(query as CFDictionary)
        
        // errSecItemNotFound is okay - item already doesn't exist
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.invalidStatus(status)
        }
    }
    
    public func deleteAllTokens() throws {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service
        ]
        
        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        
        let status = SecItemDelete(query as CFDictionary)
        
        // errSecItemNotFound is okay - no items exist
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.invalidStatus(status)
        }
    }
    
    // MARK: - Additional Methods
    
    /// Check if a token exists for the given key
    public func hasToken(forKey key: String) -> Bool {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecReturnData as String: false,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess
    }
    
    /// Update an existing token
    public func updateToken(_ token: String, forKey key: String) throws {
        guard let data = token.data(using: .utf8) else {
            throw KeychainError.conversionFailed
        }
        
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key
        ]
        
        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        
        let attributesToUpdate: [String: Any] = [
            kSecValueData as String: data
        ]
        
        let status = SecItemUpdate(query as CFDictionary, attributesToUpdate as CFDictionary)
        
        if status == errSecItemNotFound {
            // Item doesn't exist, create it
            try saveToken(token, forKey: key)
        } else if status != errSecSuccess {
            throw KeychainError.invalidStatus(status)
        }
    }
    
    /// Get all stored token keys
    public func getAllTokenKeys() -> [String] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        
        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess,
              let items = result as? [[String: Any]] else {
            return []
        }
        
        return items.compactMap { $0[kSecAttrAccount as String] as? String }
    }
    
    /// Save data to keychain
    public func saveData(_ data: Data, forKey key: String) throws {
        // Delete existing item first
        try? deleteToken(forKey: key)
        
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            kSecAttrAccessible as String: accessibility
        ]
        
        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        
        let status = SecItemAdd(query as CFDictionary, nil)
        
        guard status == errSecSuccess else {
            throw KeychainError.invalidStatus(status)
        }
    }
    
    /// Retrieve data from keychain
    public func getData(forKey key: String) -> Data? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess,
              let data = result as? Data else {
            return nil
        }
        
        return data
    }
}

// MARK: - KeychainStorage + Convenience

public extension KeychainStorage {
    /// Save a Session to keychain
    func saveSession(_ session: Session) throws {
        try saveToken(session.accessToken, forKey: TokenStorageKeys.accessToken)
        try saveToken(session.refreshToken, forKey: TokenStorageKeys.refreshToken)
        
        let expiresAtString = String(session.expiresAt.timeIntervalSince1970)
        try saveToken(expiresAtString, forKey: TokenStorageKeys.sessionExpiresAt)
    }
    
    /// Retrieve a Session from keychain
    func getSession() -> Session? {
        guard let accessToken = getToken(forKey: TokenStorageKeys.accessToken),
              let refreshToken = getToken(forKey: TokenStorageKeys.refreshToken),
              let expiresAtString = getToken(forKey: TokenStorageKeys.sessionExpiresAt),
              let expiresAt = TimeInterval(expiresAtString) else {
            return nil
        }
        
        return Session(
            accessToken: accessToken,
            refreshToken: refreshToken,
            expiresAt: Date(timeIntervalSince1970: expiresAt)
        )
    }
    
    /// Delete the stored session
    func deleteSession() throws {
        try deleteToken(forKey: TokenStorageKeys.accessToken)
        try deleteToken(forKey: TokenStorageKeys.refreshToken)
        try deleteToken(forKey: TokenStorageKeys.sessionExpiresAt)
    }
}
