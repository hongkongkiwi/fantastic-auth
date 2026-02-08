import SwiftUI
import Combine

// MARK: - VaultAuthState

@available(iOS 14.0, *)
@propertyWrapper
public struct VaultAuthState: DynamicProperty {
    @StateObject private var authState = AuthStateObject()
    
    public var wrappedValue: User? {
        authState.currentUser
    }
    
    public var projectedValue: AuthStateObject {
        authState
    }
    
    public init() {}
}

// MARK: - AuthStateObject

@available(iOS 14.0, *)
public class AuthStateObject: ObservableObject {
    @Published public private(set) var currentUser: User?
    @Published public private(set) var currentOrganization: Organization?
    @Published public private(set) var organizations: [Organization] = []
    @Published public private(set) var isAuthenticated: Bool = false
    @Published public private(set) var isLoading: Bool = false
    
    private var cancellables = Set<AnyCancellable>()
    
    public init() {
        // Subscribe to VaultAuth changes
        VaultAuth.shared.$currentUser
            .receive(on: DispatchQueue.main)
            .sink { [weak self] user in
                self?.currentUser = user
                self?.isAuthenticated = user != nil
            }
            .store(in: &cancellables)
        
        VaultAuth.shared.$currentOrganization
            .receive(on: DispatchQueue.main)
            .sink { [weak self] org in
                self?.currentOrganization = org
            }
            .store(in: &cancellables)
        
        VaultAuth.shared.$organizations
            .receive(on: DispatchQueue.main)
            .sink { [weak self] orgs in
                self?.organizations = orgs
            }
            .store(in: &cancellables)
        
        VaultAuth.shared.$isLoading
            .receive(on: DispatchQueue.main)
            .sink { [weak self] loading in
                self?.isLoading = loading
            }
            .store(in: &cancellables)
        
        // Initial sync
        currentUser = VaultAuth.shared.currentUser
        currentOrganization = VaultAuth.shared.currentOrganization
        organizations = VaultAuth.shared.organizations
        isAuthenticated = VaultAuth.shared.isAuthenticated
    }
    
    // MARK: - Actions
    
    @discardableResult
    public func login(email: String, password: String) async throws -> User {
        return try await VaultAuth.shared.login(email: email, password: password)
    }
    
    @discardableResult
    public func loginWithBiometric() async throws -> User {
        return try await VaultAuth.shared.loginWithBiometric()
    }
    
    @discardableResult
    public func signup(email: String, password: String, name: String?) async throws -> User {
        return try await VaultAuth.shared.signup(email: email, password: password, name: name)
    }
    
    public func logout() async throws {
        try await VaultAuth.shared.logout()
    }
    
    public func refreshSession() async throws {
        try await VaultAuth.shared.refreshSession()
    }
    
    public func switchOrganization(_ organizationId: String) async throws -> Organization {
        return try await VaultAuth.shared.switchOrganization(organizationId)
    }
    
    @discardableResult
    public func loginWithOAuth(
        provider: OAuthProvider,
        from viewController: UIViewController
    ) async throws -> User {
        return try await VaultAuth.shared.loginWithOAuth(provider: provider, from: viewController)
    }
    
    // MARK: - Biometric
    
    public var canUseBiometricLogin: Bool {
        BiometricAuth.shared.canUseBiometricLogin
    }
    
    public var biometricType: BiometricType {
        BiometricAuth.shared.biometricType
    }
    
    public func enableBiometricLogin(email: String, password: String) async throws -> Bool {
        return try await BiometricAuth.shared.enableBiometricLogin(email: email, password: password)
    }
    
    public func disableBiometricLogin() throws {
        try BiometricAuth.shared.disableBiometricLogin()
    }
}

// MARK: - View Modifiers

@available(iOS 14.0, *)
public struct VaultAuthRequiredModifier: ViewModifier {
    @VaultAuthState var authState
    
    let onAuthenticated: (User) -> Void
    let onUnauthenticated: () -> Void
    
    public func body(content: Content) -> some View {
        content
            .onAppear {
                if let user = authState.currentUser {
                    onAuthenticated(user)
                } else {
                    onUnauthenticated()
                }
            }
            .onChange(of: authState.currentUser) { user in
                if let user = user {
                    onAuthenticated(user)
                } else {
                    onUnauthenticated()
                }
            }
    }
}

@available(iOS 14.0, *)
public extension View {
    func vaultAuthRequired(
        onAuthenticated: @escaping (User) -> Void,
        onUnauthenticated: @escaping () -> Void
    ) -> some View {
        modifier(VaultAuthRequiredModifier(
            onAuthenticated: onAuthenticated,
            onUnauthenticated: onUnauthenticated
        ))
    }
}

// MARK: - VaultAuthViewModel

@available(iOS 14.0, *)
public class VaultAuthViewModel: ObservableObject {
    @Published public var isAuthenticated = false
    @Published public var currentUser: User?
    @Published public var isLoading = false
    @Published public var error: Error?
    
    private var cancellables = Set<AnyCancellable>()
    
    public init() {
        VaultAuth.shared.$currentUser
            .receive(on: DispatchQueue.main)
            .sink { [weak self] user in
                self?.currentUser = user
                self?.isAuthenticated = user != nil
            }
            .store(in: &cancellables)
        
        VaultAuth.shared.$isLoading
            .receive(on: DispatchQueue.main)
            .sink { [weak self] loading in
                self?.isLoading = loading
            }
            .store(in: &cancellables)
        
        // Initial sync
        currentUser = VaultAuth.shared.currentUser
        isAuthenticated = VaultAuth.shared.isAuthenticated
    }
    
    public func logout() async {
        do {
            try await VaultAuth.shared.logout()
        } catch {
            self.error = error
        }
    }
}

// MARK: - Environment Values

@available(iOS 14.0, *)
private struct VaultAuthKey: EnvironmentKey {
    static let defaultValue = VaultAuth.shared
}

@available(iOS 14.0, *)
public extension EnvironmentValues {
    var vaultAuth: VaultAuth {
        get { self[VaultAuthKey.self] }
        set { self[VaultAuthKey.self] = newValue }
    }
}

// MARK: - View Extensions

@available(iOS 14.0, *)
public extension View {
    func vaultAuth(_ vaultAuth: VaultAuth = .shared) -> some View {
        environment(\.vaultAuth, vaultAuth)
    }
}
