import Foundation
import Combine

/// The authentication service for managing user sign-in and sign-up.
///
/// Use this class to authenticate users with various methods including
/// email/password, magic links, and biometric authentication.
public actor VaultAuth {
    
    // MARK: - Properties
    
    private let apiClient: APIClient
    private let tokenStore: TokenStore
    
    // MARK: - Initialization
    
    init(apiClient: APIClient, tokenStore: TokenStore) {
        self.apiClient = apiClient
        self.tokenStore = tokenStore
    }
    
    // MARK: - Email/Password Authentication
    
    /// Signs in a user with email and password.
    ///
    /// - Parameters:
    ///   - email: The user's email address
    ///   - password: The user's password
    /// - Returns: The session containing the user and tokens
    /// - Throws: `VaultError` if authentication fails
    public func signIn(email: String, password: String) async throws -> VaultSession {
        // Validate inputs
        guard email.isValidEmail else {
            throw ValidationError.invalidEmail
        }
        guard !password.isEmpty else {
            throw ValidationError.requiredField("Password")
        }
        
        let request = SignInRequest(email: email, password: password)
        let response: AuthResponse = try await apiClient.post(
            path: "/v1/auth/signin",
            body: request,
            requiresAuth: false
        )
        
        // Store tokens
        await tokenStore.setTokens(
            accessToken: response.accessToken,
            refreshToken: response.refreshToken
        )
        
        Vault.shared.logger.log("User signed in: \(response.user.id)")
        
        return Vault.shared.session
    }
    
    /// Signs up a new user with email and password.
    ///
    /// - Parameters:
    ///   - email: The user's email address
    ///   - password: The user's password
    ///   - firstName: Optional first name
    ///   - lastName: Optional last name
    /// - Returns: The session containing the user and tokens
    /// - Throws: `VaultError` if sign-up fails
    public func signUp(
        email: String,
        password: String,
        firstName: String? = nil,
        lastName: String? = nil
    ) async throws -> VaultSession {
        // Validate inputs
        guard email.isValidEmail else {
            throw ValidationError.invalidEmail
        }
        guard password.count >= 8 else {
            throw ValidationError.tooShort(field: "Password", minLength: 8)
        }
        
        let request = SignUpRequest(
            email: email,
            password: password,
            firstName: firstName,
            lastName: lastName
        )
        let response: AuthResponse = try await apiClient.post(
            path: "/v1/auth/signup",
            body: request,
            requiresAuth: false
        )
        
        // Store tokens
        await tokenStore.setTokens(
            accessToken: response.accessToken,
            refreshToken: response.refreshToken
        )
        
        Vault.shared.logger.log("User signed up: \(response.user.id)")
        
        return Vault.shared.session
    }
    
    /// Signs in with a biometric key.
    ///
    /// This requires that a biometric key has been previously generated and registered.
    ///
    /// - Returns: The session if authentication succeeds
    /// - Throws: `VaultError` if biometric authentication fails
    public func signInWithBiometric() async throws -> VaultSession {
        let biometric = Vault.shared.biometric
        
        guard biometric.isAvailable else {
            throw VaultError.biometricNotAvailable
        }
        
        // Get the stored private key
        guard let privateKey = try await biometric.getStoredKey() else {
            throw VaultError.keyNotFound
        }
        
        // Generate a challenge from the server
        let challenge: ChallengeResponse = try await apiClient.post(
            path: "/v1/auth/biometric/challenge",
            body: ["tenant_id": Vault.shared.configuration?.tenantId],
            requiresAuth: false
        )
        
        // Sign the challenge with the private key
        let signature = try await biometric.signChallenge(challenge.challenge, with: privateKey)
        
        // Verify the signature with the server
        let verifyRequest = BiometricVerifyRequest(
            challengeId: challenge.id,
            signature: signature,
            keyId: challenge.keyId
        )
        let response: AuthResponse = try await apiClient.post(
            path: "/v1/auth/biometric/verify",
            body: verifyRequest,
            requiresAuth: false
        )
        
        // Store tokens
        await tokenStore.setTokens(
            accessToken: response.accessToken,
            refreshToken: response.refreshToken
        )
        
        Vault.shared.logger.log("User signed in with biometric: \(response.user.id)")
        
        return Vault.shared.session
    }
    
    /// Registers biometric authentication for the current user.
    ///
    /// This generates a new key pair in the Secure Enclave and registers the public key
    /// with the Vault server.
    ///
    /// - Throws: `VaultError` if registration fails
    public func registerBiometric() async throws {
        let biometric = Vault.shared.biometric
        
        guard biometric.isAvailable else {
            throw VaultError.biometricNotAvailable
        }
        
        // Generate a new key pair in Secure Enclave
        let publicKey = try await biometric.generateAndStoreKey()
        
        // Get the public key data
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, nil) else {
            throw VaultError.keyGenerationFailed("Failed to export public key")
        }
        
        // Register with server
        let request = RegisterBiometricRequest(
            publicKey: (publicKeyData as Data).base64EncodedString(),
            deviceName: await UIDevice.current.name
        )
        let _: EmptyResponse = try await apiClient.post(
            path: "/v1/auth/biometric/register",
            body: request
        )
        
        Vault.shared.logger.log("Biometric authentication registered")
    }
    
    /// Unregisters biometric authentication for the current user.
    ///
    /// - Throws: `VaultError` if unregistration fails
    public func unregisterBiometric() async throws {
        // Delete from server
        let _: EmptyResponse = try await apiClient.delete(path: "/v1/auth/biometric")
        
        // Delete local key
        try await Vault.shared.biometric.deleteStoredKey()
        
        Vault.shared.logger.log("Biometric authentication unregistered")
    }
    
    // MARK: - Password Management
    
    /// Requests a password reset email.
    ///
    /// - Parameter email: The email address to send the reset link to
    /// - Throws: `VaultError` if the request fails
    public func requestPasswordReset(email: String) async throws {
        guard email.isValidEmail else {
            throw ValidationError.invalidEmail
        }
        
        let request = PasswordResetRequest(email: email)
        let _: EmptyResponse = try await apiClient.post(
            path: "/v1/auth/password/reset",
            body: request,
            requiresAuth: false
        )
        
        Vault.shared.logger.log("Password reset requested for: \(email)")
    }
    
    /// Updates the current user's password.
    ///
    /// - Parameters:
    ///   - currentPassword: The current password
    ///   - newPassword: The new password
    /// - Throws: `VaultError` if the update fails
    public func updatePassword(currentPassword: String, newPassword: String) async throws {
        guard newPassword.count >= 8 else {
            throw ValidationError.tooShort(field: "New password", minLength: 8)
        }
        
        let request = UpdatePasswordRequest(
            currentPassword: currentPassword,
            newPassword: newPassword
        )
        let _: EmptyResponse = try await apiClient.post(
            path: "/v1/auth/password",
            body: request
        )
        
        Vault.shared.logger.log("Password updated")
    }
    
    // MARK: - Email Verification
    
    /// Verifies the user's email address.
    ///
    /// - Parameter token: The verification token from the email
    /// - Throws: `VaultError` if verification fails
    public func verifyEmail(token: String) async throws {
        let request = VerifyEmailRequest(token: token)
        let _: EmptyResponse = try await apiClient.post(
            path: "/v1/auth/verify-email",
            body: request,
            requiresAuth: false
        )
        
        Vault.shared.logger.log("Email verified")
    }
    
    /// Resends the verification email.
    ///
    /// - Throws: `VaultError` if the request fails
    public func resendVerificationEmail() async throws {
        let _: EmptyResponse = try await apiClient.post(
            path: "/v1/auth/resend-verification",
            body: EmptyRequest()
        )
        
        Vault.shared.logger.log("Verification email resent")
    }
    
    // MARK: - Session Management
    
    /// Refreshes the current session.
    ///
    /// - Returns: `true` if the session was refreshed successfully
    public func refreshSession() async -> Bool {
        guard let refreshToken = await tokenStore.getRefreshToken() else {
            return false
        }
        
        do {
            let request = RefreshTokenRequest(refreshToken: refreshToken)
            let response: TokenResponse = try await apiClient.post(
                path: "/v1/auth/refresh",
                body: request,
                requiresAuth: false
            )
            
            await tokenStore.setTokens(
                accessToken: response.accessToken,
                refreshToken: response.refreshToken
            )
            
            Vault.shared.logger.log("Session refreshed")
            return true
        } catch {
            Vault.shared.logger.logError("Failed to refresh session: \(error)")
            return false
        }
    }
}

// MARK: - Request/Response Types

internal struct AuthResponse: Decodable {
    let user: UserResponse
    let accessToken: String
    let refreshToken: String
    let expiresIn: Int
}

internal struct UserResponse: Decodable {
    let id: String
    let email: String
    let firstName: String?
    let lastName: String?
    let emailVerified: Bool
    let createdAt: String
    let updatedAt: String
    let organizations: [OrganizationResponse]?
}

internal struct OrganizationResponse: Decodable {
    let id: String
    let name: String
    let slug: String
    let role: String
}

internal struct TokenResponse: Decodable {
    let accessToken: String
    let refreshToken: String
    let expiresIn: Int
}

internal struct ChallengeResponse: Decodable {
    let id: String
    let challenge: String
    let keyId: String
}

internal struct BiometricVerifyRequest: Encodable {
    let challengeId: String
    let signature: String
    let keyId: String
}

internal struct RegisterBiometricRequest: Encodable {
    let publicKey: String
    let deviceName: String
}

internal struct EmptyRequest: Encodable {}

// MARK: - String Extensions

extension String {
    var isValidEmail: Bool {
        let regex = "^[A-Z0-9a-z._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$"
        return NSPredicate(format: "SELF MATCHES %@", regex).evaluate(with: self)
    }
}
