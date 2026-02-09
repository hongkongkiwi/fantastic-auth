import XCTest
@testable import Vault

@MainActor
final class VaultTests: XCTestCase {
    
    // MARK: - Setup
    
    override func setUp() async throws {
        try await super.setUp()
        
        // Reset Vault state
        Vault.shared.reset()
        
        // Configure Vault with test settings
        Vault.configure(
            apiUrl: "https://api.test.vault.dev",
            tenantId: "test-tenant",
            debugMode: true
        )
    }
    
    override func tearDown() async throws {
        Vault.shared.reset()
        try await super.tearDown()
    }
    
    // MARK: - Configuration Tests
    
    func testConfiguration() {
        XCTAssertTrue(Vault.shared.isConfigured)
        XCTAssertEqual(Vault.shared.configuration?.tenantId, "test-tenant")
        XCTAssertEqual(Vault.shared.configuration?.apiUrl, "https://api.test.vault.dev")
    }
    
    func testVersion() {
        XCTAssertEqual(Vault.version, "1.0.0")
    }
    
    // MARK: - User Model Tests
    
    func testUserCreation() {
        let user = VaultUser(
            id: "user-123",
            email: "test@example.com",
            firstName: "John",
            lastName: "Doe",
            emailVerified: true
        )
        
        XCTAssertEqual(user.id, "user-123")
        XCTAssertEqual(user.email, "test@example.com")
        XCTAssertEqual(user.fullName, "John Doe")
        XCTAssertEqual(user.initials, "JD")
        XCTAssertTrue(user.emailVerified)
        XCTAssertFalse(user.hasOrganizations)
    }
    
    func testUserWithoutName() {
        let user = VaultUser(
            id: "user-456",
            email: "test@example.com"
        )
        
        XCTAssertEqual(user.fullName, "")
        XCTAssertEqual(user.initials, "")
    }
    
    func testUserWithOrganizations() {
        let orgs = [
            VaultOrganizationMembership(
                id: "org-1",
                name: "Acme Corp",
                slug: "acme",
                role: .member
            )
        ]
        
        let user = VaultUser(
            id: "user-789",
            email: "test@example.com",
            organizations: orgs
        )
        
        XCTAssertTrue(user.hasOrganizations)
        XCTAssertEqual(user.organizations.count, 1)
    }
    
    // MARK: - Organization Role Tests
    
    func testOrganizationRoles() {
        XCTAssertTrue(OrganizationRole.owner.canManageMembers)
        XCTAssertTrue(OrganizationRole.owner.canManageBilling)
        XCTAssertTrue(OrganizationRole.owner.canDeleteOrganization)
        
        XCTAssertTrue(OrganizationRole.admin.canManageMembers)
        XCTAssertFalse(OrganizationRole.admin.canManageBilling)
        XCTAssertFalse(OrganizationRole.admin.canDeleteOrganization)
        
        XCTAssertFalse(OrganizationRole.member.canManageMembers)
        XCTAssertFalse(OrganizationRole.member.canManageBilling)
        XCTAssertFalse(OrganizationRole.member.canDeleteOrganization)
        
        XCTAssertEqual(OrganizationRole.owner.displayName, "Owner")
        XCTAssertEqual(OrganizationRole.admin.displayName, "Admin")
        XCTAssertEqual(OrganizationRole.member.displayName, "Member")
        XCTAssertEqual(OrganizationRole.guest.displayName, "Guest")
    }
    
    // MARK: - OAuth Provider Tests
    
    func testOAuthProviders() {
        XCTAssertEqual(OAuthProvider.apple.displayName, "Apple")
        XCTAssertEqual(OAuthProvider.google.displayName, "Google")
        XCTAssertEqual(OAuthProvider.microsoft.displayName, "Microsoft")
        XCTAssertEqual(OAuthProvider.github.displayName, "GitHub")
    }
    
    func testOAuthProviderId() {
        for provider in OAuthProvider.allCases {
            XCTAssertEqual(provider.id, provider.rawValue)
        }
    }
    
    // MARK: - Session State Tests
    
    func testSessionStateEquality() {
        let user1 = VaultUser(id: "user-1", email: "test1@example.com")
        let user2 = VaultUser(id: "user-1", email: "test1@example.com")
        let user3 = VaultUser(id: "user-2", email: "test2@example.com")
        
        XCTAssertEqual(SessionState.unauthenticated, SessionState.unauthenticated)
        XCTAssertEqual(SessionState.authenticated(user1), SessionState.authenticated(user2))
        XCTAssertNotEqual(SessionState.authenticated(user1), SessionState.authenticated(user3))
        XCTAssertNotEqual(SessionState.unauthenticated, SessionState.refreshing)
    }
    
    // MARK: - Error Tests
    
    func testVaultErrorDescriptions() {
        XCTAssertFalse(VaultError.notConfigured.localizedDescription.isEmpty)
        XCTAssertFalse(VaultError.invalidURL.localizedDescription.isEmpty)
        XCTAssertFalse(VaultError.unauthorized.localizedDescription.isEmpty)
        XCTAssertFalse(VaultError.biometricNotAvailable.localizedDescription.isEmpty)
    }
    
    func testVaultErrorEquality() {
        XCTAssertEqual(VaultError.unauthorized, VaultError.unauthorized)
        XCTAssertEqual(VaultError.conflict("test"), VaultError.conflict("test"))
        XCTAssertNotEqual(VaultError.conflict("test"), VaultError.conflict("other"))
        XCTAssertEqual(VaultError.serverError(500), VaultError.serverError(500))
        XCTAssertNotEqual(VaultError.serverError(500), VaultError.serverError(502))
    }
    
    func testRetryableErrors() {
        XCTAssertTrue(VaultError.networkError(NSError(domain: "test", code: 1)).isRetryable)
        XCTAssertTrue(VaultError.rateLimited.isRetryable)
        XCTAssertTrue(VaultError.serverError(500).isRetryable)
        
        XCTAssertFalse(VaultError.unauthorized.isRetryable)
        XCTAssertFalse(VaultError.invalidURL.isRetryable)
        XCTAssertFalse(VaultError.biometricNotAvailable.isRetryable)
    }
    
    // MARK: - Crypto Tests
    
    func testSHA256() {
        let input = "hello world"
        let hash = VaultCrypto.sha256(input)
        XCTAssertEqual(hash.count, 64) // Hex string length
        
        // Verify deterministic
        let hash2 = VaultCrypto.sha256(input)
        XCTAssertEqual(hash, hash2)
        
        // Verify different inputs produce different hashes
        let hash3 = VaultCrypto.sha256("different")
        XCTAssertNotEqual(hash, hash3)
    }
    
    func testRandomBytes() throws {
        let bytes1 = try VaultCrypto.randomBytes(count: 32)
        let bytes2 = try VaultCrypto.randomBytes(count: 32)
        
        XCTAssertEqual(bytes1.count, 32)
        XCTAssertEqual(bytes2.count, 32)
        XCTAssertNotEqual(bytes1, bytes2) // Should be random
    }
    
    func testRandomString() {
        let str1 = VaultCrypto.randomString(length: 16)
        let str2 = VaultCrypto.randomString(length: 16)
        
        XCTAssertEqual(str1.count, 16)
        XCTAssertEqual(str2.count, 16)
        XCTAssertNotEqual(str1, str2) // Should be random
    }
    
    func testBase64Encoding() {
        let data = "Hello, World!".data(using: .utf8)!
        let encoded = VaultCrypto.base64Encode(data)
        let decoded = VaultCrypto.base64Decode(encoded)
        
        XCTAssertEqual(decoded, data)
    }
    
    func testBase64URLEncoding() {
        let data = Data([0xFB, 0xFF, 0xFE]) // Contains + and / in regular base64
        let encoded = VaultCrypto.base64URLEncode(data)
        
        XCTAssertFalse(encoded.contains("+"))
        XCTAssertFalse(encoded.contains("/"))
        XCTAssertFalse(encoded.contains("="))
        
        let decoded = VaultCrypto.base64URLDecode(encoded)
        XCTAssertEqual(decoded, data)
    }
    
    func testPasswordStrength() {
        XCTAssertEqual(VaultCrypto.passwordStrength("a"), 0) // Very weak
        XCTAssertEqual(VaultCrypto.passwordStrength("password"), 1) // Weak
        XCTAssertEqual(VaultCrypto.passwordStrength("Password1"), 2) // Medium
        XCTAssertEqual(VaultCrypto.passwordStrength("Password1!"), 3) // Strong
        XCTAssertEqual(VaultCrypto.passwordStrength("MyStr0ng!Pass"), 4) // Very strong
    }
    
    func testGeneratePassword() {
        let password1 = VaultCrypto.generatePassword()
        let password2 = VaultCrypto.generatePassword()
        
        XCTAssertEqual(password1.count, 16)
        XCTAssertEqual(password2.count, 16)
        XCTAssertNotEqual(password1, password2)
        
        let customLength = VaultCrypto.generatePassword(length: 24)
        XCTAssertEqual(customLength.count, 24)
    }
    
    func testGenerateUUID() {
        let uuid1 = VaultCrypto.generateUUID()
        let uuid2 = VaultCrypto.generateUUID()
        
        XCTAssertNotEqual(uuid1, uuid2)
        XCTAssertEqual(uuid1.split(separator: "-").count, 5) // UUID format
    }
    
    func testHMAC() {
        let message = "hello"
        let key = "secret"
        let hmac1 = VaultCrypto.hmacSHA256(message, key: key)
        let hmac2 = VaultCrypto.hmacSHA256(message, key: key)
        let hmac3 = VaultCrypto.hmacSHA256("different", key: key)
        
        XCTAssertEqual(hmac1, hmac2) // Deterministic
        XCTAssertNotEqual(hmac1, hmac3) // Different message
        XCTAssertFalse(hmac1.isEmpty)
    }
    
    // MARK: - Data Extension Tests
    
    func testDataHexEncoding() {
        let data = Data([0x00, 0x0F, 0xFF])
        XCTAssertEqual(data.hexEncodedString, "000fff")
    }
    
    func testDataHexDecoding() {
        let hex = "48656c6c6f" // "Hello"
        let data = Data(hex: hex)
        XCTAssertEqual(data, "Hello".data(using: .utf8))
    }
    
    func testInvalidHexDecoding() {
        XCTAssertNil(Data(hex: "xyz"))
        XCTAssertNil(Data(hex: "abc")) // Odd length
    }
    
    // MARK: - String Extension Tests
    
    func testStringSHA256() {
        let hash1 = "test".sha256
        let hash2 = VaultCrypto.sha256("test")
        XCTAssertEqual(hash1, hash2)
    }
    
    func testStringBase64() {
        let original = "Hello, World!"
        let encoded = original.base64Encoded!
        let decoded = encoded.base64Decoded!
        XCTAssertEqual(original, decoded)
    }
    
    // MARK: - Biometric Type Tests
    
    func testBiometricTypeDisplayName() {
        XCTAssertEqual(BiometricType.faceID.displayName, "Face ID")
        XCTAssertEqual(BiometricType.touchID.displayName, "Touch ID")
        XCTAssertEqual(BiometricType.opticID.displayName, "Optic ID")
        XCTAssertEqual(BiometricType.none.displayName, "None")
    }
    
    // MARK: - Preferences Tests
    
    func testUserPreferences() {
        let prefs = UserPreferences(
            useBiometric: true,
            language: "fr",
            theme: .dark,
            notificationsEnabled: false
        )
        
        XCTAssertTrue(prefs.useBiometric)
        XCTAssertEqual(prefs.language, "fr")
        XCTAssertEqual(prefs.theme, .dark)
        XCTAssertFalse(prefs.notificationsEnabled)
    }
    
    func testDefaultUserPreferences() {
        let prefs = UserPreferences()
        
        XCTAssertFalse(prefs.useBiometric)
        XCTAssertEqual(prefs.language, "en")
        XCTAssertEqual(prefs.theme, .system)
        XCTAssertTrue(prefs.notificationsEnabled)
    }
    
    // MARK: - Theme Tests
    
    func testThemeCases() {
        XCTAssertEqual(Theme.allCases.count, 3)
        XCTAssertTrue(Theme.allCases.contains(.light))
        XCTAssertTrue(Theme.allCases.contains(.dark))
        XCTAssertTrue(Theme.allCases.contains(.system))
    }
    
    // MARK: - Async Tests
    
    func testSessionStateStream() async throws {
        let states = Vault.shared.session.stateStream()
        
        // Should start with unauthenticated
        var iterator = states.makeAsyncIterator()
        let firstState = await iterator.next()
        XCTAssertEqual(firstState, .unauthenticated)
    }
}

// MARK: - Mock Tests

/// Mock API client for testing.
actor MockAPIClient {
    var responses: [String: Decodable] = [:]
    var errors: [String: VaultError] = [:]
    
    func setResponse<T: Decodable>(_ response: T, for path: String) {
        responses[path] = response
    }
    
    func setError(_ error: VaultError, for path: String) {
        errors[path] = error
    }
}

// MARK: - Performance Tests

extension VaultTests {
    func testSHA256Performance() {
        let data = Data(repeating: 0xFF, count: 1000000)
        
        measure {
            _ = VaultCrypto.sha256(data)
        }
    }
    
    func testRandomBytesPerformance() {
        measure {
            _ = try? VaultCrypto.randomBytes(count: 1024)
        }
    }
}
