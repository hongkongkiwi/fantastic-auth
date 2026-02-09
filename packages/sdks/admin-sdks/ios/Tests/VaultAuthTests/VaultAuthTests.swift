import XCTest
@testable import VaultAuth

final class VaultAuthTests: XCTestCase {
    
    // MARK: - Setup
    
    override func setUp() {
        super.setUp()
        // Reset any stored state before each test
        let storage = InMemoryTokenStorage()
        try? storage.deleteAllTokens()
    }
    
    override func tearDown() {
        super.tearDown()
    }
    
    // MARK: - TokenStorage Tests
    
    func testInMemoryTokenStorage() throws {
        let storage = InMemoryTokenStorage()
        
        // Test save and retrieve
        try storage.saveToken("test_token", forKey: "test_key")
        XCTAssertEqual(storage.getToken(forKey: "test_key"), "test_token")
        
        // Test update
        try storage.saveToken("updated_token", forKey: "test_key")
        XCTAssertEqual(storage.getToken(forKey: "test_key"), "updated_token")
        
        // Test delete
        try storage.deleteToken(forKey: "test_key")
        XCTAssertNil(storage.getToken(forKey: "test_key"))
        
        // Test delete all
        try storage.saveToken("token1", forKey: "key1")
        try storage.saveToken("token2", forKey: "key2")
        try storage.deleteAllTokens()
        XCTAssertNil(storage.getToken(forKey: "key1"))
        XCTAssertNil(storage.getToken(forKey: "key2"))
    }
    
    func testUserDefaultsTokenStorage() throws {
        let userDefaults = UserDefaults(suiteName: "test_suite")!
        let storage = UserDefaultsTokenStorage(userDefaults: userDefaults, prefix: "test_")
        
        try storage.saveToken("test_token", forKey: "test_key")
        XCTAssertEqual(storage.getToken(forKey: "test_key"), "test_token")
        
        // Cleanup
        try storage.deleteAllTokens()
    }
    
    // MARK: - User Model Tests
    
    func testUserDecoding() throws {
        let json = """
        {
            "id": "user_123",
            "email": "test@example.com",
            "name": "Test User",
            "avatar_url": "https://example.com/avatar.jpg",
            "email_verified": true,
            "created_at": "2024-01-01T00:00:00.000Z",
            "updated_at": "2024-01-01T00:00:00.000Z",
            "roles": ["admin"],
            "permissions": ["read", "write"]
        }
        """
        
        let data = json.data(using: .utf8)!
        let user = try JSONDecoder().decode(User.self, from: data)
        
        XCTAssertEqual(user.id, "user_123")
        XCTAssertEqual(user.email, "test@example.com")
        XCTAssertEqual(user.name, "Test User")
        XCTAssertEqual(user.avatarUrl, "https://example.com/avatar.jpg")
        XCTAssertTrue(user.emailVerified)
        XCTAssertEqual(user.roles, ["admin"])
        XCTAssertEqual(user.permissions, ["read", "write"])
    }
    
    func testUserEquality() {
        let user1 = User(id: "1", email: "test@example.com", name: "Test")
        let user2 = User(id: "1", email: "different@example.com", name: "Different")
        let user3 = User(id: "2", email: "test@example.com", name: "Test")
        
        XCTAssertEqual(user1.id, user2.id)
        XCTAssertNotEqual(user1.id, user3.id)
    }
    
    // MARK: - Session Tests
    
    func testSessionValidity() {
        let future = Date().addingTimeInterval(3600) // 1 hour from now
        let past = Date().addingTimeInterval(-3600) // 1 hour ago
        
        let validSession = Session(
            accessToken: "token",
            refreshToken: "refresh",
            expiresAt: future
        )
        XCTAssertTrue(validSession.isValid)
        XCTAssertFalse(validSession.isExpiringSoon)
        
        let expiredSession = Session(
            accessToken: "token",
            refreshToken: "refresh",
            expiresAt: past
        )
        XCTAssertFalse(expiredSession.isValid)
        
        let expiringSoon = Date().addingTimeInterval(60) // 1 minute from now
        let expiringSession = Session(
            accessToken: "token",
            refreshToken: "refresh",
            expiresAt: expiringSoon
        )
        XCTAssertTrue(expiringSession.isValid)
        XCTAssertTrue(expiringSession.isExpiringSoon)
    }
    
    // MARK: - Organization Tests
    
    func testOrganizationRolePermissions() {
        XCTAssertTrue(OrganizationRole.owner.canManageMembers)
        XCTAssertTrue(OrganizationRole.owner.canManageSettings)
        XCTAssertTrue(OrganizationRole.admin.canManageMembers)
        XCTAssertTrue(OrganizationRole.admin.canManageSettings)
        XCTAssertFalse(OrganizationRole.member.canManageMembers)
        XCTAssertFalse(OrganizationRole.viewer.canManageSettings)
        
        XCTAssertEqual(OrganizationRole.owner.permissions, ["*"])
        XCTAssertTrue(OrganizationRole.admin.permissions.contains("org:members:write"))
        XCTAssertFalse(OrganizationRole.member.permissions.contains("org:members:write"))
    }
    
    func testOrganizationDecoding() throws {
        let json = """
        {
            "id": "org_123",
            "name": "Test Org",
            "slug": "test-org",
            "logo_url": "https://example.com/logo.png",
            "description": "A test organization",
            "website": "https://example.com",
            "created_at": "2024-01-01T00:00:00.000Z",
            "updated_at": "2024-01-01T00:00:00.000Z",
            "member_count": 10,
            "role": "admin",
            "settings": {
                "mfa_required": true,
                "sso_enabled": false,
                "allow_signups": true
            }
        }
        """
        
        let data = json.data(using: .utf8)!
        let org = try JSONDecoder().decode(Organization.self, from: data)
        
        XCTAssertEqual(org.id, "org_123")
        XCTAssertEqual(org.name, "Test Org")
        XCTAssertEqual(org.slug, "test-org")
        XCTAssertEqual(org.role, .admin)
        XCTAssertEqual(org.memberCount, 10)
        XCTAssertTrue(org.settings?.mfaRequired ?? false)
    }
    
    // MARK: - Error Tests
    
    func testVaultAuthErrorDescriptions() {
        XCTAssertEqual(VaultAuthError.notConfigured.errorDescription, "VaultAuth has not been configured. Call configure() first.")
        XCTAssertEqual(VaultAuthError.invalidCredentials.errorDescription, "Invalid email or password.")
        XCTAssertEqual(VaultAuthError.sessionExpired.errorDescription, "Your session has expired. Please log in again.")
        XCTAssertEqual(VaultAuthError.biometricNotAvailable.errorDescription, "Biometric authentication is not available on this device.")
    }
    
    func testVaultAuthErrorRetryable() {
        XCTAssertTrue(VaultAuthError.networkError(NSError(domain: "test", code: 1)).isRetryable)
        XCTAssertTrue(VaultAuthError.serverError(500, nil).isRetryable)
        XCTAssertFalse(VaultAuthError.invalidCredentials.isRetryable)
        XCTAssertFalse(VaultAuthError.biometricFailed.isRetryable)
    }
    
    // MARK: - BiometricAuth Tests
    
    func testBiometricTypeDisplayNames() {
        XCTAssertEqual(BiometricType.none.displayName, "None")
        XCTAssertEqual(BiometricType.touchID.displayName, "Touch ID")
        XCTAssertEqual(BiometricType.faceID.displayName, "Face ID")
        XCTAssertEqual(BiometricType.opticID.displayName, "Optic ID")
    }
    
    func testBiometricCredentialsEncoding() throws {
        let credentials = BiometricCredentials(email: "test@example.com", password: "password123")
        
        let encoder = JSONEncoder()
        let data = try encoder.encode(credentials)
        
        let decoder = JSONDecoder()
        let decoded = try decoder.decode(BiometricCredentials.self, from: data)
        
        XCTAssertEqual(decoded.email, "test@example.com")
        XCTAssertEqual(decoded.password, "password123")
    }
    
    // MARK: - MFA Tests
    
    func testMFAMethodDisplayNames() {
        XCTAssertEqual(MFAMethod.totp.displayName, "Authenticator App")
        XCTAssertEqual(MFAMethod.sms.displayName, "SMS")
        XCTAssertEqual(MFAMethod.email.displayName, "Email")
        XCTAssertEqual(MFAMethod.push.displayName, "Push Notification")
    }
    
    func testMFAMethodRawValues() {
        XCTAssertEqual(MFAMethod.totp.rawValue, "totp")
        XCTAssertEqual(MFAMethod.sms.rawValue, "sms")
        XCTAssertEqual(MFAMethod.email.rawValue, "email")
        XCTAssertEqual(MFAMethod.push.rawValue, "push")
    }
    
    // MARK: - OAuth Tests
    
    func testOAuthProviderDisplayNames() {
        XCTAssertEqual(OAuthProvider.google.displayName, "Google")
        XCTAssertEqual(OAuthProvider.apple.displayName, "Apple")
        XCTAssertEqual(OAuthProvider.microsoft.displayName, "Microsoft")
        XCTAssertEqual(OAuthProvider.github.displayName, "GitHub")
        XCTAssertEqual(OAuthProvider.facebook.displayName, "Facebook")
    }
    
    func testOAuthProviderRawValues() {
        XCTAssertEqual(OAuthProvider.google.rawValue, "google")
        XCTAssertEqual(OAuthProvider.apple.rawValue, "apple")
        XCTAssertEqual(OAuthProvider.microsoft.rawValue, "microsoft")
        XCTAssertEqual(OAuthProvider.github.rawValue, "github")
        XCTAssertEqual(OAuthProvider.facebook.rawValue, "facebook")
    }
    
    // MARK: - Theme Tests
    
    func testVaultThemeDefaultValues() {
        let theme = VaultTheme.default
        
        XCTAssertEqual(theme.primaryColor, .systemBlue)
        XCTAssertEqual(theme.backgroundColor, .systemBackground)
        XCTAssertEqual(theme.cornerRadius, 8)
        XCTAssertEqual(theme.padding, 24)
    }
    
    func testVaultThemeCustomization() {
        let customTheme = VaultTheme(
            primaryColor: .red,
            cornerRadius: 16,
            padding: 32
        )
        
        XCTAssertEqual(customTheme.primaryColor, .red)
        XCTAssertEqual(customTheme.cornerRadius, 16)
        XCTAssertEqual(customTheme.padding, 32)
    }
    
    // MARK: - Notification Tests
    
    func testNotificationNames() {
        XCTAssertEqual(Notification.Name.mfaRequestReceived.rawValue, "VaultMFARequestReceived")
        XCTAssertEqual(Notification.Name.biometricLoginEnabled.rawValue, "VaultBiometricLoginEnabled")
        XCTAssertEqual(Notification.Name.sessionRevoked.rawValue, "VaultSessionRevoked")
    }
}

// MARK: - Integration Tests

final class VaultAuthIntegrationTests: XCTestCase {
    
    func testSessionSaveAndRetrieve() throws {
        let storage = InMemoryTokenStorage()
        let keychainStorage = KeychainStorage(service: "com.vault.test")
        
        let session = Session(
            accessToken: "access_token_123",
            refreshToken: "refresh_token_456",
            expiresAt: Date().addingTimeInterval(3600)
        )
        
        // Test KeychainStorage session methods
        try keychainStorage.saveSession(session)
        let retrievedSession = keychainStorage.getSession()
        
        XCTAssertNotNil(retrievedSession)
        XCTAssertEqual(retrievedSession?.accessToken, session.accessToken)
        XCTAssertEqual(retrievedSession?.refreshToken, session.refreshToken)
        
        // Cleanup
        try keychainStorage.deleteSession()
    }
    
    func testPasswordStrength() {
        // Weak password
        let weak = calculateStrength("password")
        XCTAssertEqual(weak, .weak)
        
        // Fair password
        let fair = calculateStrength("Password1")
        XCTAssertEqual(fair, .fair)
        
        // Good password
        let good = calculateStrength("Password1!")
        XCTAssertEqual(good, .good)
        
        // Strong password
        let strong = calculateStrength("MyStr0ng!Pass#2024")
        XCTAssertEqual(strong, .strong)
    }
    
    private func calculateStrength(_ password: String) -> PasswordStrength {
        var score = 0
        if password.count >= 8 { score += 1 }
        if password.count >= 12 { score += 1 }
        if password.rangeOfCharacter(from: .uppercaseLetters) != nil { score += 1 }
        if password.rangeOfCharacter(from: .lowercaseLetters) != nil { score += 1 }
        if password.rangeOfCharacter(from: .decimalDigits) != nil { score += 1 }
        if password.rangeOfCharacter(from: CharacterSet(charactersIn: "!@#$%^&*()_+-=[]{}|;:,.<>?")) != nil { score += 1 }
        
        switch score {
        case 0...2: return .weak
        case 3...4: return .fair
        case 5...6: return .good
        default: return .strong
        }
    }
}

// MARK: - PasswordStrength Helper

enum PasswordStrength: Equatable {
    case weak
    case fair
    case good
    case strong
}

// MARK: - Mock Classes

class MockTokenStorage: TokenStorage {
    var storage: [String: String] = [:]
    var shouldFail = false
    
    func saveToken(_ token: String, forKey key: String) throws {
        if shouldFail { throw KeychainError.invalidStatus(errSecDuplicateItem) }
        storage[key] = token
    }
    
    func getToken(forKey key: String) -> String? {
        return storage[key]
    }
    
    func deleteToken(forKey key: String) throws {
        if shouldFail { throw KeychainError.itemNotFound }
        storage.removeValue(forKey: key)
    }
    
    func deleteAllTokens() throws {
        storage.removeAll()
    }
}

class MockBiometricContext: BiometricContext {
    var mockBiometricType: BiometricType = .faceID
    var mockAvailable = true
    var mockEnrolled = true
    var shouldSucceed = true
    var shouldCancel = false
    
    var biometricType: BiometricType { mockBiometricType }
    var isAvailable: Bool { mockAvailable }
    var isEnrolled: Bool { mockEnrolled }
    
    func canEvaluatePolicy(_ policy: LAPolicy, error: NSErrorPointer) -> Bool {
        return mockAvailable && mockEnrolled
    }
    
    func evaluatePolicy(_ policy: LAPolicy, localizedReason: String, reply: @escaping (Bool, Error?) -> Void) {
        if shouldCancel {
            reply(false, NSError(domain: LAError.errorDomain, code: LAError.userCancel.rawValue))
        } else {
            reply(shouldSucceed, shouldSucceed ? nil : NSError(domain: "test", code: 1))
        }
    }
}
