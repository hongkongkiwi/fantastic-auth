import Foundation
import Combine

/// Manages the user's session state.
///
/// Use this class to check authentication status, get the current user,
/// and sign out.
public actor VaultSession {
    
    // MARK: - Properties
    
    private let tokenStore: TokenStore
    private let apiClient: APIClient
    
    /// The current user, if authenticated.
    private var user: VaultUser?
    
    /// Whether the session is currently being refreshed.
    private var isRefreshing = false
    
    /// Subject for publishing state changes.
    private let stateSubject = CurrentValueSubject<SessionState, Never>(.unauthenticated)
    
    /// Publisher for session state changes.
    nonisolated var statePublisher: AnyPublisher<SessionState, Never> {
        stateSubject.eraseToAnyPublisher()
    }
    
    // MARK: - Public Properties
    
    /// The current session state.
    nonisolated public var currentState: SessionState {
        stateSubject.value
    }
    
    /// The current user, if authenticated.
    public var currentUser: VaultUser? {
        get { user }
    }
    
    /// Whether a user is currently signed in.
    public var isAuthenticated: Bool {
        user != nil
    }
    
    /// Whether the session is valid (has tokens).
    public var isValid: Bool {
        get async {
            await tokenStore.getAccessToken() != nil
        }
    }
    
    // MARK: - Initialization
    
    init(tokenStore: TokenStore, apiClient: APIClient) {
        self.tokenStore = tokenStore
        self.apiClient = apiClient
        
        // Check for existing session
        Task {
            await restoreSession()
        }
    }
    
    // MARK: - Public Methods
    
    /// Restores the session from stored tokens.
    ///
    /// This is called automatically on initialization but can be called
    /// manually to force a session restore.
    ///
    /// - Returns: `true` if a valid session was restored
    public func restoreSession() async -> Bool {
        guard let accessToken = await tokenStore.getAccessToken() else {
            stateSubject.send(.unauthenticated)
            return false
        }
        
        // Set state to refreshing
        stateSubject.send(.refreshing)
        
        do {
            // Fetch current user to validate token
            let user = try await fetchCurrentUser()
            self.user = user
            stateSubject.send(.authenticated(user))
            Vault.shared.logger.log("Session restored for user: \(user.id)")
            return true
        } catch {
            // Token might be expired, try to refresh
            if await Vault.shared.auth.refreshSession() {
                do {
                    let user = try await fetchCurrentUser()
                    self.user = user
                    stateSubject.send(.authenticated(user))
                    return true
                } catch {
                    await clearSession()
                    return false
                }
            } else {
                await clearSession()
                return false
            }
        }
    }
    
    /// Signs the current user out.
    ///
    /// This clears all stored tokens and session data.
    public func signOut() async {
        // Notify server about sign out
        _ = try? await apiClient.post(
            path: "/v1/auth/signout",
            body: EmptyRequest()
        )
        
        await clearSession()
        Vault.shared.logger.log("User signed out")
    }
    
    /// Gets a valid access token.
    ///
    /// This automatically refreshes the token if it's expired.
    ///
    /// - Returns: A valid access token, or `nil` if not authenticated
    public func getToken() async -> String? {
        // Check if we have a token
        if let token = await tokenStore.getAccessToken() {
            return token
        }
        
        // Try to refresh
        if await Vault.shared.auth.refreshSession() {
            return await tokenStore.getAccessToken()
        }
        
        return nil
    }
    
    /// Gets the current refresh token.
    ///
    /// - Returns: The refresh token, or `nil` if not authenticated
    public func getRefreshToken() async -> String? {
        await tokenStore.getRefreshToken()
    }
    
    /// Updates the current user.
    ///
    /// This is called internally when user data changes.
    /// - Parameter user: The updated user
    internal func updateUser(_ user: VaultUser) {
        self.user = user
        stateSubject.send(.authenticated(user))
    }
    
    /// Invalidates the current session.
    ///
    /// This is called when the server returns a 401 unauthorized.
    public func invalidate() async {
        await clearSession()
        Vault.shared.logger.log("Session invalidated")
    }
    
    // MARK: - Combine Support
    
    /// Returns a publisher that emits when the authentication state changes.
    ///
    /// - Returns: A publisher of session states
    nonisolated public func stateStream() -> AsyncStream<SessionState> {
        AsyncStream { continuation in
            let cancellable = statePublisher.sink { state in
                continuation.yield(state)
            }
            
            continuation.onTermination = { _ in
                cancellable.cancel()
            }
        }
    }
    
    /// Waits for the user to be authenticated.
    ///
    /// This is useful for SwiftUI views that need to wait for authentication.
    /// - Returns: The authenticated user
    /// - Throws: `VaultError.sessionExpired` if the session expires while waiting
    public func waitForAuthentication() async throws -> VaultUser {
        if let user = currentUser {
            return user
        }
        
        for await state in stateStream() {
            switch state {
            case .authenticated(let user):
                return user
            case .unauthenticated:
                throw VaultError.sessionExpired
            case .refreshing:
                continue
            }
        }
        
        throw VaultError.sessionExpired
    }
    
    // MARK: - Private Methods
    
    private func fetchCurrentUser() async throws -> VaultUser {
        let response: UserResponse = try await apiClient.get(path: "/v1/users/me")
        return mapUserResponse(response)
    }
    
    private func clearSession() async {
        await tokenStore.clearTokens()
        user = nil
        stateSubject.send(.unauthenticated)
    }
    
    private func mapUserResponse(_ response: UserResponse) -> VaultUser {
        let dateFormatter = ISO8601DateFormatter()
        
        return VaultUser(
            id: response.id,
            email: response.email,
            firstName: response.firstName,
            lastName: response.lastName,
            emailVerified: response.emailVerified,
            createdAt: dateFormatter.date(from: response.createdAt) ?? Date(),
            updatedAt: dateFormatter.date(from: response.updatedAt) ?? Date(),
            organizations: response.organizations?.map { org in
                VaultOrganizationMembership(
                    id: org.id,
                    name: org.name,
                    slug: org.slug,
                    role: OrganizationRole(rawValue: org.role) ?? .member,
                    isActive: false
                )
            } ?? []
        )
    }
}

// MARK: - Session Observer

/// A helper class for observing session changes in SwiftUI.
@MainActor
public final class SessionObserver: ObservableObject {
    
    // MARK: - Properties
    
    @Published public private(set) var state: SessionState = .unauthenticated
    @Published public private(set) var isAuthenticated = false
    @Published public private(set) var currentUser: VaultUser?
    
    private var cancellable: AnyCancellable?
    
    // MARK: - Initialization
    
    public init() {
        self.cancellable = Vault.shared.session.statePublisher
            .receive(on: DispatchQueue.main)
            .sink { [weak self] state in
                self?.state = state
                self?.isAuthenticated = state != .unauthenticated
                if case .authenticated(let user) = state {
                    self?.currentUser = user
                } else {
                    self?.currentUser = nil
                }
            }
    }
    
    deinit {
        cancellable?.cancel()
    }
}

// MARK: - SwiftUI View Modifiers

import SwiftUI

/// A view modifier that observes session state.
private struct SessionObserverModifier: ViewModifier {
    @StateObject private var observer = SessionObserver()
    
    func body(content: Content) -> some View {
        content
            .environmentObject(observer)
    }
}

public extension View {
    /// Observes the Vault session and updates when it changes.
    func observeVaultSession() -> some View {
        modifier(SessionObserverModifier())
    }
}

// MARK: - Environment Keys

private struct SessionObserverKey: EnvironmentKey {
    static let defaultValue: SessionObserver? = nil
}

public extension EnvironmentValues {
    var vaultSessionObserver: SessionObserver? {
        get { self[SessionObserverKey.self] }
        set { self[SessionObserverKey.self] = newValue }
    }
}
