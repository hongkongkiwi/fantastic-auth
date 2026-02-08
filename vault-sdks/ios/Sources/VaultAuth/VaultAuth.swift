import Foundation
import UIKit
import AuthenticationServices

// MARK: - VaultAuth

public class VaultAuth: NSObject, ObservableObject {
    
    // MARK: - Singleton
    
    public static let shared = VaultAuth()
    
    // MARK: - Properties
    
    private var vaultClient: VaultClient?
    private var tokenStorage: TokenStorage
    private var pushManager: PushNotificationManager
    
    private var apiKey: String?
    private var baseURL: String?
    private var tenantId: String?
    
    @Published public private(set) var currentUser: User?
    @Published public private(set) var currentOrganization: Organization?
    @Published public private(set) var organizations: [Organization] = []
    @Published public private(set) var isLoading = false
    
    public var isAuthenticated: Bool {
        return currentUser != nil && getSession()?.isValid == true
    }
    
    private var webAuthSession: ASWebAuthenticationSession?
    
    // MARK: - Initialization
    
    public init(tokenStorage: TokenStorage = KeychainStorage()) {
        self.tokenStorage = tokenStorage
        self.pushManager = PushNotificationManager()
        super.init()
        
        // Try to restore session
        Task {
            await restoreSession()
        }
    }
    
    // MARK: - Configuration
    
    public func configure(
        apiKey: String,
        baseURL: String,
        tenantId: String? = nil,
        tokenStorage: TokenStorage? = nil
    ) {
        self.apiKey = apiKey
        self.baseURL = baseURL
        self.tenantId = tenantId
        
        if let tokenStorage = tokenStorage {
            self.tokenStorage = tokenStorage
        }
        
        guard let url = URL(string: baseURL) else {
            print("Invalid base URL: \(baseURL)")
            return
        }
        
        self.vaultClient = VaultClient(
            baseURL: url,
            apiKey: apiKey,
            tenantId: tenantId
        )
        
        self.pushManager.configure(with: vaultClient!)
        
        // Update client with stored token if available
        if let session = getSession() {
            vaultClient?.setAccessToken(session.accessToken)
        }
        
        // Process any pending push notifications
        pushManager.processPendingNotifications()
    }
    
    // MARK: - Authentication Methods
    
    @discardableResult
    public func login(email: String, password: String) async throws -> User {
        guard let client = vaultClient else {
            throw VaultAuthError.notConfigured
        }
        
        isLoading = true
        defer { isLoading = false }
        
        let request = LoginRequest(
            email: email,
            password: password,
            tenantId: tenantId
        )
        
        do {
            let response: AuthResponse = try await client.post("/auth/login", body: request)
            try await handleAuthResponse(response)
            return response.user
        } catch VaultAuthError.mfaRequired {
            // MFA is required - the caller needs to handle this
            throw VaultAuthError.mfaRequired
        } catch {
            throw error
        }
    }
    
    @discardableResult
    public func loginWithBiometric() async throws -> User {
        guard BiometricAuth.shared.canUseBiometricLogin else {
            throw VaultAuthError.biometricNotAvailable
        }
        
        guard let credentials = try await BiometricAuth.shared.getBiometricCredentials() else {
            throw VaultAuthError.biometricFailed
        }
        
        return try await login(email: credentials.email, password: credentials.password)
    }
    
    @discardableResult
    public func signup(email: String, password: String, name: String? = nil) async throws -> User {
        guard let client = vaultClient else {
            throw VaultAuthError.notConfigured
        }
        
        isLoading = true
        defer { isLoading = false }
        
        let request = SignupRequest(
            email: email,
            password: password,
            name: name,
            tenantId: tenantId
        )
        
        let response: AuthResponse = try await client.post("/auth/signup", body: request)
        try await handleAuthResponse(response)
        return response.user
    }
    
    public func logout() async throws {
        guard let client = vaultClient else {
            throw VaultAuthError.notConfigured
        }
        
        do {
            try await client.post("/auth/logout")
        } catch {
            // Continue with local logout even if server logout fails
        }
        
        // Unregister push notifications
        await pushManager.unregisterDevice()
        
        // Clear local session
        try clearSession()
    }
    
    // MARK: - Token Verification
    
    @discardableResult
    public func verifyToken(_ token: String) async throws -> User {
        guard let client = vaultClient else {
            throw VaultAuthError.notConfigured
        }
        
        let request = TokenVerificationRequest(token: token)
        let user: User = try await client.post("/auth/verify", body: request)
        
        return user
    }
    
    // MARK: - Session Management
    
    public func refreshSession() async throws {
        guard let client = vaultClient else {
            throw VaultAuthError.notConfigured
        }
        
        guard let session = getSession() else {
            throw VaultAuthError.tokenNotFound
        }
        
        isLoading = true
        defer { isLoading = false }
        
        let request = TokenRefreshRequest(refreshToken: session.refreshToken)
        
        do {
            let response: TokenRefreshResponse = try await client.post("/auth/refresh", body: request)
            
            let newSession = Session(
                accessToken: response.accessToken,
                refreshToken: session.refreshToken,
                expiresAt: response.expiresAt,
                tokenType: response.tokenType
            )
            
            try saveSession(newSession)
            client.setAccessToken(newSession.accessToken)
            
            // Refresh user info
            let user: User = try await client.get("/auth/me")
            await MainActor.run {
                self.currentUser = user
            }
        } catch {
            // Clear session on refresh failure
            try? clearSession()
            throw VaultAuthError.tokenRefreshFailed
        }
    }
    
    @discardableResult
    private func restoreSession() async -> Bool {
        guard let client = vaultClient ?? createClientFromStoredConfig(),
              let session = getSession() else {
            return false
        }
        
        // Check if session is valid or needs refresh
        if session.isValid {
            client.setAccessToken(session.accessToken)
            await MainActor.run {
                self.vaultClient = client
            }
            
            // Fetch current user
            do {
                let user: User = try await client.get("/auth/me")
                await MainActor.run {
                    self.currentUser = user
                }
                return true
            } catch {
                return false
            }
        } else if session.isExpiringSoon || !session.isValid {
            // Try to refresh
            do {
                try await refreshSession()
                return true
            } catch {
                return false
            }
        }
        
        return false
    }
    
    // MARK: - OAuth
    
    @discardableResult
    public func loginWithOAuth(
        provider: OAuthProvider,
        from viewController: UIViewController
    ) async throws -> User {
        guard let client = vaultClient,
              let baseURL = baseURL else {
            throw VaultAuthError.notConfigured
        }
        
        let redirectUri = "vaultauth://oauth/callback"
        let state = UUID().uuidString
        
        let request = OAuthRequest(
            provider: provider.rawValue,
            redirectUri: redirectUri,
            state: state,
            tenantId: tenantId
        )
        
        // Get OAuth URL from server
        let response: OAuthInitResponse = try await client.post("/auth/oauth/init", body: request)
        
        guard let authURL = URL(string: response.authorizationUrl) else {
            throw VaultAuthError.oauthFailed("Invalid authorization URL")
        }
        
        return try await withCheckedThrowingContinuation { continuation in
            let session = ASWebAuthenticationSession(
                url: authURL,
                callbackURLScheme: "vaultauth"
            ) { callbackURL, error in
                if let error = error {
                    if (error as NSError).code == ASWebAuthenticationSessionError.canceledLogin.rawValue {
                        continuation.resume(throwing: VaultAuthError.oauthCancelled)
                    } else {
                        continuation.resume(throwing: VaultAuthError.oauthFailed(error.localizedDescription))
                    }
                    return
                }
                
                guard let callbackURL = callbackURL else {
                    continuation.resume(throwing: VaultAuthError.oauthFailed("No callback URL"))
                    return
                }
                
                // Parse callback URL
                guard let components = URLComponents(url: callbackURL, resolvingAgainstBaseURL: true),
                      let code = components.queryItems?.first(where: { $0.name == "code" })?.value,
                      let returnedState = components.queryItems?.first(where: { $0.name == "state" })?.value,
                      returnedState == state else {
                    continuation.resume(throwing: VaultAuthError.oauthFailed("Invalid callback"))
                    return
                }
                
                // Exchange code for tokens
                Task {
                    do {
                        let callbackRequest = OAuthCallbackRequest(
                            code: code,
                            state: state,
                            tenantId: self.tenantId
                        )
                        
                        let authResponse: AuthResponse = try await client.post("/auth/oauth/callback", body: callbackRequest)
                        try await self.handleAuthResponse(authResponse)
                        continuation.resume(returning: authResponse.user)
                    } catch {
                        continuation.resume(throwing: error)
                    }
                }
            }
            
            session.presentationContextProvider = self
            session.prefersEphemeralWebBrowserSession = false
            
            self.webAuthSession = session
            session.start()
        }
    }
    
    // MARK: - MFA
    
    public func enableMFA(method: MFAMethod) async throws -> MFAEnableResponse {
        guard let client = vaultClient else {
            throw VaultAuthError.notConfigured
        }
        
        let request = MFAEnableRequest(method: method.rawValue)
        let response: MFAEnableResponse = try await client.post("/auth/mfa/enable", body: request)
        return response
    }
    
    @discardableResult
    public func verifyMFA(code: String, method: MFAMethod? = nil) async throws -> User {
        guard let client = vaultClient else {
            throw VaultAuthError.notConfigured
        }
        
        let request = MFAVerifyRequest(code: code, method: method?.rawValue)
        let response: AuthResponse = try await client.post("/auth/mfa/verify", body: request)
        try await handleAuthResponse(response)
        return response.user
    }
    
    public func disableMFA(method: MFAMethod, code: String) async throws {
        guard let client = vaultClient else {
            throw VaultAuthError.notConfigured
        }
        
        let request = MFADisableRequest(code: code, method: method.rawValue)
        try await client.post("/auth/mfa/disable", body: request)
    }
    
    // MARK: - Organizations
    
    public func getOrganizations() async throws -> [Organization] {
        guard let client = vaultClient else {
            throw VaultAuthError.notConfigured
        }
        
        let response: OrganizationListResponse = try await client.get("/auth/organizations")
        
        await MainActor.run {
            self.organizations = response.organizations
        }
        
        return response.organizations
    }
    
    @discardableResult
    public func switchOrganization(_ organizationId: String) async throws -> Organization {
        guard let client = vaultClient else {
            throw VaultAuthError.notConfigured
        }
        
        let request = OrganizationSwitchRequest(organizationId: organizationId)
        let organization: Organization = try await client.post("/auth/organizations/switch", body: request)
        
        await MainActor.run {
            self.currentOrganization = organization
        }
        
        // Store current organization
        try? tokenStorage.saveToken(organizationId, forKey: TokenStorageKeys.organizationId)
        
        return organization
    }
    
    // MARK: - Push Notifications
    
    public func registerForPushNotifications(deviceToken: Data) {
        pushManager.registerDevice(token: deviceToken)
    }
    
    public func handlePushNotification(_ notification: [AnyHashable: Any]) {
        pushManager.handleNotification(notification)
    }
    
    public var pushNotificationHandler: PushNotificationHandler? {
        guard let client = vaultClient else { return nil }
        return PushNotificationHandler(vaultClient: client)
    }
    
    // MARK: - Private Helpers
    
    private func handleAuthResponse(_ response: AuthResponse) async throws {
        // Save session
        try saveSession(response.session)
        
        // Update client with new token
        vaultClient?.setAccessToken(response.session.accessToken)
        
        // Update published properties on main thread
        await MainActor.run {
            self.currentUser = response.user
        }
        
        // Fetch organizations
        do {
            let orgs = try await getOrganizations()
            if let firstOrg = orgs.first, currentOrganization == nil {
                _ = try? await switchOrganization(firstOrg.id)
            }
        } catch {
            // Non-critical error
        }
    }
    
    private func saveSession(_ session: Session) throws {
        if let keychainStorage = tokenStorage as? KeychainStorage {
            try keychainStorage.saveSession(session)
        } else {
            try tokenStorage.saveToken(session.accessToken, forKey: TokenStorageKeys.accessToken)
            try tokenStorage.saveToken(session.refreshToken, forKey: TokenStorageKeys.refreshToken)
            try tokenStorage.saveToken(String(session.expiresAt.timeIntervalSince1970), forKey: TokenStorageKeys.sessionExpiresAt)
        }
        
        vaultClient?.setAccessToken(session.accessToken)
    }
    
    private func getSession() -> Session? {
        if let keychainStorage = tokenStorage as? KeychainStorage {
            return keychainStorage.getSession()
        }
        
        guard let accessToken = tokenStorage.getToken(forKey: TokenStorageKeys.accessToken),
              let refreshToken = tokenStorage.getToken(forKey: TokenStorageKeys.refreshToken),
              let expiresAtString = tokenStorage.getToken(forKey: TokenStorageKeys.sessionExpiresAt),
              let expiresAt = TimeInterval(expiresAtString) else {
            return nil
        }
        
        return Session(
            accessToken: accessToken,
            refreshToken: refreshToken,
            expiresAt: Date(timeIntervalSince1970: expiresAt)
        )
    }
    
    private func clearSession() throws {
        if let keychainStorage = tokenStorage as? KeychainStorage {
            try keychainStorage.deleteSession()
        } else {
            try tokenStorage.deleteToken(forKey: TokenStorageKeys.accessToken)
            try tokenStorage.deleteToken(forKey: TokenStorageKeys.refreshToken)
            try tokenStorage.deleteToken(forKey: TokenStorageKeys.sessionExpiresAt)
        }
        
        try tokenStorage.deleteToken(forKey: TokenStorageKeys.organizationId)
        
        await MainActor.run {
            self.currentUser = nil
            self.currentOrganization = nil
            self.organizations = []
        }
        
        vaultClient?.setAccessToken(nil)
    }
    
    private func createClientFromStoredConfig() -> VaultClient? {
        // This would need to store/retrieve config from UserDefaults or similar
        // For now, return nil
        return nil
    }
}

// MARK: - ASWebAuthenticationPresentationContextProviding

extension VaultAuth: ASWebAuthenticationPresentationContextProviding {
    public func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        return UIApplication.shared.windows.first { $0.isKeyWindow } ?? UIWindow()
    }
}

// MARK: - OAuthInitResponse

struct OAuthInitResponse: Decodable {
    let authorizationUrl: String
}
