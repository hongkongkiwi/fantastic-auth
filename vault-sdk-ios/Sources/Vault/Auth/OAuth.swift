import Foundation
import AuthenticationServices
import Combine

/// OAuth providers supported by Vault.
public enum OAuthProvider: String, CaseIterable, Identifiable {
    case apple = "apple"
    case google = "google"
    case microsoft = "microsoft"
    case github = "github"
    case gitlab = "gitlab"
    case discord = "discord"
    case slack = "slack"
    case twitter = "twitter"
    case facebook = "facebook"
    case linkedin = "linkedin"
    
    public var id: String { rawValue }
    
    /// The display name for the provider.
    public var displayName: String {
        switch self {
        case .apple: return "Apple"
        case .google: return "Google"
        case .microsoft: return "Microsoft"
        case .github: return "GitHub"
        case .gitlab: return "GitLab"
        case .discord: return "Discord"
        case .slack: return "Slack"
        case .twitter: return "X (Twitter)"
        case .facebook: return "Facebook"
        case .linkedin: return "LinkedIn"
        }
    }
    
    /// The SF Symbol name for the provider icon.
    public var iconName: String {
        switch self {
        case .apple: return "apple.logo"
        case .google, .microsoft, .github, .gitlab, .discord, .slack, .twitter, .facebook, .linkedin:
            return "globe"
        }
    }
}

/// The OAuth service for social authentication.
///
/// Use this class to authenticate users with OAuth providers like Apple, Google,
/// Microsoft, and others.
public actor VaultOAuth {
    
    // MARK: - Properties
    
    private let apiClient: APIClient
    private let tokenStore: TokenStore
    
    /// Continuation for handling OAuth callbacks.
    private var oauthContinuation: CheckedContinuation<String, Error>?
    
    /// The current OAuth session.
    private var currentSession: ASWebAuthenticationSession?
    
    // MARK: - Initialization
    
    init(apiClient: APIClient, tokenStore: TokenStore) {
        self.apiClient = apiClient
        self.tokenStore = tokenStore
    }
    
    // MARK: - OAuth Sign In
    
    /// Signs in with an OAuth provider.
    ///
    /// This method presents the OAuth provider's authentication flow and returns
    /// a session upon successful authentication.
    ///
    /// - Parameters:
    ///   - provider: The OAuth provider to use
    ///   - presentationContextProvider: Optional context provider for the web session
    /// - Returns: The session containing the user and tokens
    /// - Throws: `VaultError` if authentication fails
    @MainActor
    public func signIn(
        with provider: OAuthProvider,
        presentationContextProvider: ASWebAuthenticationPresentationContextProviding? = nil
    ) async throws -> VaultSession {
        // Get the authorization URL from the server
        let authUrlResponse: OAuthUrlResponse = try await apiClient.get(
            path: "/v1/auth/oauth/\(provider.rawValue)/authorize",
            requiresAuth: false
        )
        
        guard let authURL = URL(string: authUrlResponse.url) else {
            throw VaultError.invalidURL
        }
        
        // Create the callback URL scheme
        let callbackScheme = "vault://oauth/callback"
        
        // Perform OAuth flow
        let callbackURL = try await withCheckedThrowingContinuation { continuation in
            let session = ASWebAuthenticationSession(
                url: authURL,
                callbackURLScheme: callbackScheme
            ) { callbackURL, error in
                if let error = error {
                    if let authError = error as? ASWebAuthenticationSessionError,
                       authError.code == .canceledLogin {
                        continuation.resume(throwing: VaultError.userCancelled)
                    } else {
                        continuation.resume(throwing: VaultError.oauthFailed(error.localizedDescription))
                    }
                    return
                }
                
                guard let callbackURL = callbackURL else {
                    continuation.resume(throwing: VaultError.oauthFailed("No callback URL received"))
                    return
                }
                
                continuation.resume(returning: callbackURL)
            }
            
            session.presentationContextProvider = presentationContextProvider ?? VaultPresentationContext.shared
            session.prefersEphemeralWebBrowserSession = false
            
            self.currentSession = session
            session.start()
        }
        
        // Extract the authorization code from the callback
        guard let code = extractCode(from: callbackURL) else {
            throw VaultError.oauthFailed("No authorization code in callback")
        }
        
        // Exchange code for tokens
        let request = OAuthRequest(
            provider: provider.rawValue,
            code: code,
            redirectUri: callbackScheme
        )
        
        let response: AuthResponse = try await apiClient.post(
            path: "/v1/auth/oauth/callback",
            body: request,
            requiresAuth: false
        )
        
        // Store tokens
        await tokenStore.setTokens(
            accessToken: response.accessToken,
            refreshToken: response.refreshToken
        )
        
        Vault.shared.logger.log("User signed in with \(provider.displayName)")
        
        return Vault.shared.session
    }
    
    /// Signs in with Sign in with Apple.
    ///
    /// This uses the native Sign in with Apple flow for the best user experience.
    ///
    /// - Parameters:
    ///   - request: Optional custom authorization request
    /// - Returns: The session containing the user and tokens
    /// - Throws: `VaultError` if authentication fails
    @MainActor
    public func signInWithApple(
        request: ASAuthorizationAppleIDRequest? = nil
    ) async throws -> VaultSession {
        try await withCheckedThrowingContinuation { continuation in
            let provider = ASAuthorizationAppleIDProvider()
            let authRequest = request ?? provider.createRequest()
            
            // Configure the request
            if request == nil {
                authRequest.requestedScopes = [.fullName, .email]
            }
            
            let controller = ASAuthorizationController(authorizationRequests: [authRequest])
            let delegate = SignInWithAppleDelegate { result in
                switch result {
                case .success(let credential):
                    Task {
                        do {
                            let session = try await self.handleAppleCredential(credential)
                            continuation.resume(returning: session)
                        } catch {
                            continuation.resume(throwing: error)
                        }
                    }
                case .failure(let error):
                    continuation.resume(throwing: VaultError.oauthFailed(error.localizedDescription))
                }
            }
            
            controller.delegate = delegate
            controller.presentationContextProvider = delegate
            controller.performRequests()
            
            // Keep delegate alive
            objc_setAssociatedObject(controller, "delegate", delegate, .OBJC_ASSOCIATION_RETAIN)
        }
    }
    
    /// Links an OAuth provider to the current user.
    ///
    /// - Parameters:
    ///   - provider: The OAuth provider to link
    ///   - presentationContextProvider: Optional context provider for the web session
    /// - Throws: `VaultError` if linking fails
    @MainActor
    public func linkProvider(
        _ provider: OAuthProvider,
        presentationContextProvider: ASWebAuthenticationPresentationContextProviding? = nil
    ) async throws {
        // Get the authorization URL from the server
        let authUrlResponse: OAuthUrlResponse = try await apiClient.get(
            path: "/v1/auth/oauth/\(provider.rawValue)/link"
        )
        
        guard let authURL = URL(string: authUrlResponse.url) else {
            throw VaultError.invalidURL
        }
        
        let callbackScheme = "vault://oauth/link"
        
        let callbackURL = try await withCheckedThrowingContinuation { continuation in
            let session = ASWebAuthenticationSession(
                url: authURL,
                callbackURLScheme: callbackScheme
            ) { callbackURL, error in
                if let error = error {
                    if let authError = error as? ASWebAuthenticationSessionError,
                       authError.code == .canceledLogin {
                        continuation.resume(throwing: VaultError.userCancelled)
                    } else {
                        continuation.resume(throwing: VaultError.oauthFailed(error.localizedDescription))
                    }
                    return
                }
                
                guard let callbackURL = callbackURL else {
                    continuation.resume(throwing: VaultError.oauthFailed("No callback URL received"))
                    return
                }
                
                continuation.resume(returning: callbackURL)
            }
            
            session.presentationContextProvider = presentationContextProvider ?? VaultPresentationContext.shared
            session.prefersEphemeralWebBrowserSession = false
            
            self.currentSession = session
            session.start()
        }
        
        guard let code = extractCode(from: callbackURL) else {
            throw VaultError.oauthFailed("No authorization code in callback")
        }
        
        let request = OAuthLinkRequest(
            provider: provider.rawValue,
            code: code
        )
        
        let _: EmptyResponse = try await apiClient.post(
            path: "/v1/auth/oauth/link/callback",
            body: request
        )
        
        Vault.shared.logger.log("Linked \(provider.displayName) to user account")
    }
    
    /// Unlinks an OAuth provider from the current user.
    ///
    /// - Parameter provider: The OAuth provider to unlink
    /// - Throws: `VaultError` if unlinking fails
    public func unlinkProvider(_ provider: OAuthProvider) async throws {
        let _: EmptyResponse = try await apiClient.delete(
            path: "/v1/auth/oauth/\(provider.rawValue)"
        )
        
        Vault.shared.logger.log("Unlinked \(provider.displayName) from user account")
    }
    
    /// Gets the list of linked OAuth providers for the current user.
    ///
    /// - Returns: Array of linked OAuth providers
    /// - Throws: `VaultError` if the request fails
    public func getLinkedProviders() async throws -> [OAuthProvider] {
        let response: LinkedProvidersResponse = try await apiClient.get(
            path: "/v1/auth/oauth/providers"
        )
        
        return response.providers.compactMap { OAuthProvider(rawValue: $0) }
    }
    
    // MARK: - Private Methods
    
    private func extractCode(from url: URL) -> String? {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let queryItems = components.queryItems else {
            return nil
        }
        
        return queryItems.first(where: { $0.name == "code" })?.value
    }
    
    private func handleAppleCredential(_ credential: ASAuthorizationAppleIDCredential) async throws -> VaultSession {
        guard let identityToken = credential.identityToken,
              let idTokenString = String(data: identityToken, encoding: .utf8) else {
            throw VaultError.oauthFailed("No identity token received")
        }
        
        let request = SignInWithAppleRequest(
            idToken: idTokenString,
            authorizationCode: credential.authorizationCode?.base64EncodedString(),
            fullName: credential.fullName,
            email: credential.email
        )
        
        let response: AuthResponse = try await apiClient.post(
            path: "/v1/auth/apple",
            body: request,
            requiresAuth: false
        )
        
        // Store tokens
        await Vault.shared.tokenStore.setTokens(
            accessToken: response.accessToken,
            refreshToken: response.refreshToken
        )
        
        Vault.shared.logger.log("User signed in with Apple")
        
        return Vault.shared.session
    }
}

// MARK: - Supporting Types

internal struct OAuthUrlResponse: Decodable {
    let url: String
    let state: String
}

internal struct OAuthLinkRequest: Encodable {
    let provider: String
    let code: String
}

internal struct LinkedProvidersResponse: Decodable {
    let providers: [String]
}

internal struct SignInWithAppleRequest: Encodable {
    let idToken: String
    let authorizationCode: String?
    let fullName: PersonNameComponents?
    let email: String?
    
    enum CodingKeys: String, CodingKey {
        case idToken = "id_token"
        case authorizationCode = "authorization_code"
        case givenName = "given_name"
        case familyName = "family_name"
        case email
    }
    
    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(idToken, forKey: .idToken)
        try container.encodeIfPresent(authorizationCode, forKey: .authorizationCode)
        try container.encodeIfPresent(fullName?.givenName, forKey: .givenName)
        try container.encodeIfPresent(fullName?.familyName, forKey: .familyName)
        try container.encodeIfPresent(email, forKey: .email)
    }
}

// MARK: - Sign In with Apple Delegate

@MainActor
private class SignInWithAppleDelegate: NSObject, ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding {
    typealias CompletionHandler = (Result<ASAuthorizationAppleIDCredential, Error>) -> Void
    
    private let completion: CompletionHandler
    
    init(completion: @escaping CompletionHandler) {
        self.completion = completion
    }
    
    func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        if let credential = authorization.credential as? ASAuthorizationAppleIDCredential {
            completion(.success(credential))
        } else {
            completion(.failure(VaultError.oauthFailed("Invalid credential type")))
        }
    }
    
    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        completion(.failure(error))
    }
    
    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        // Get the key window
        guard let windowScene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
              let window = windowScene.windows.first else {
            fatalError("No window available")
        }
        return window
    }
}

// MARK: - Presentation Context

@MainActor
public class VaultPresentationContext: NSObject, ASWebAuthenticationPresentationContextProviding {
    public static let shared = VaultPresentationContext()
    
    public func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        guard let windowScene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
              let window = windowScene.windows.first else {
            fatalError("No window available")
        }
        return window
    }
}

// Import UIKit for UIApplication
import UIKit
