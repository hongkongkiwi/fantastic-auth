import Foundation

// MARK: - TokenStorage

public protocol TokenStorage {
    /// Save a token to storage
    func saveToken(_ token: String, forKey key: String) throws
    
    /// Retrieve a token from storage
    func getToken(forKey key: String) -> String?
    
    /// Delete a token from storage
    func deleteToken(forKey key: String) throws
    
    /// Delete all tokens from storage
    func deleteAllTokens() throws
}

// MARK: - TokenStorageKeys

public enum TokenStorageKeys {
    public static let accessToken = "vault_access_token"
    public static let refreshToken = "vault_refresh_token"
    public static let sessionExpiresAt = "vault_session_expires_at"
    public static let biometricEnabled = "vault_biometric_enabled"
    public static let userId = "vault_user_id"
    public static let organizationId = "vault_organization_id"
}

// MARK: - InMemoryTokenStorage

public class InMemoryTokenStorage: TokenStorage {
    private var storage: [String: String] = [:]
    private let queue = DispatchQueue(label: "com.vault.inmemorystorage", attributes: .concurrent)
    
    public init() {}
    
    public func saveToken(_ token: String, forKey key: String) throws {
        queue.async(flags: .barrier) {
            self.storage[key] = token
        }
    }
    
    public func getToken(forKey key: String) -> String? {
        return queue.sync {
            return storage[key]
        }
    }
    
    public func deleteToken(forKey key: String) throws {
        queue.async(flags: .barrier) {
            self.storage.removeValue(forKey: key)
        }
    }
    
    public func deleteAllTokens() throws {
        queue.async(flags: .barrier) {
            self.storage.removeAll()
        }
    }
}

// MARK: - UserDefaultsTokenStorage

public class UserDefaultsTokenStorage: TokenStorage {
    private let userDefaults: UserDefaults
    private let prefix: String
    
    public init(userDefaults: UserDefaults = .standard, prefix: String = "vault_") {
        self.userDefaults = userDefaults
        self.prefix = prefix
    }
    
    public func saveToken(_ token: String, forKey key: String) throws {
        let prefixedKey = prefix + key
        userDefaults.set(token, forKey: prefixedKey)
    }
    
    public func getToken(forKey key: String) -> String? {
        let prefixedKey = prefix + key
        return userDefaults.string(forKey: prefixedKey)
    }
    
    public func deleteToken(forKey key: String) throws {
        let prefixedKey = prefix + key
        userDefaults.removeObject(forKey: prefixedKey)
    }
    
    public func deleteAllTokens() throws {
        let keys = userDefaults.dictionaryRepresentation().keys.filter { $0.hasPrefix(prefix) }
        for key in keys {
            userDefaults.removeObject(forKey: key)
        }
    }
}
