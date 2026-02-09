import Foundation
import Combine

/// The main Vault SDK class.
///
/// Use this class to configure and interact with the Vault platform.
/// All interactions are thread-safe and use Swift concurrency.
///
/// Example usage:
/// ```swift
/// import Vault
///
/// // Configure the SDK
/// Vault.configure(
///     apiUrl: "https://api.vault.dev",
///     tenantId: "my-tenant"
/// )
///
/// // Sign in
/// let auth = VaultAuth()
/// let session = try await auth.signIn(email: "user@example.com", password: "password")
/// ```
public final class Vault {
    
    // MARK: - Singleton
    
    /// The shared Vault instance.
    public static let shared = Vault()
    
    // MARK: - Configuration
    
    /// The current configuration.
    public private(set) var configuration: Configuration?
    
    /// Configuration for the Vault SDK.
    public struct Configuration {
        /// The API URL for Vault.
        public let apiUrl: String
        
        /// The tenant identifier.
        public let tenantId: String
        
        /// Optional API key for server-side operations.
        public let apiKey: String?
        
        /// Whether to enable debug logging.
        public let debugMode: Bool
        
        /// Request timeout in seconds.
        public let timeout: TimeInterval
        
        /// The current SDK version.
        public let sdkVersion: String = "1.0.0"
        
        /// Creates a new configuration.
        ///
        /// - Parameters:
        ///   - apiUrl: The API URL for Vault (e.g., "https://api.vault.dev")
        ///   - tenantId: Your tenant identifier
        ///   - apiKey: Optional API key for admin operations
        ///   - debugMode: Enable debug logging (default: false)
        ///   - timeout: Request timeout in seconds (default: 30)
        public init(
            apiUrl: String,
            tenantId: String,
            apiKey: String? = nil,
            debugMode: Bool = false,
            timeout: TimeInterval = 30
        ) {
            self.apiUrl = apiUrl.trimmingCharacters(in: .init(charactersIn: "/"))
            self.tenantId = tenantId
            self.apiKey = apiKey
            self.debugMode = debugMode
            self.timeout = timeout
        }
    }
    
    // MARK: - Services
    
    /// The authentication service.
    public lazy var auth: VaultAuth = {
        VaultAuth(apiClient: apiClient, tokenStore: tokenStore)
    }()
    
    /// The session manager.
    public lazy var session: VaultSession = {
        VaultSession(tokenStore: tokenStore, apiClient: apiClient)
    }()
    
    /// The OAuth service.
    public lazy var oauth: VaultOAuth = {
        VaultOAuth(apiClient: apiClient, tokenStore: tokenStore)
    }()
    
    /// The biometric authentication service.
    public lazy var biometric: VaultBiometric = {
        VaultBiometric(tokenStore: tokenStore)
    }()
    
    /// The organizations service.
    public lazy var organizations: VaultOrganizations = {
        VaultOrganizations(apiClient: apiClient, session: session)
    }()
    
    // MARK: - Internal Services
    
    /// The API client.
    internal lazy var apiClient: APIClient = {
        guard let config = configuration else {
            fatalError("Vault must be configured before use. Call Vault.configure() first.")
        }
        return APIClient(configuration: config)
    }()
    
    /// The token store.
    internal let tokenStore: TokenStore = TokenStore()
    
    /// The logger.
    internal let logger = VaultLogger()
    
    // MARK: - Combine Publishers
    
    /// Publisher that emits when the session state changes.
    public var sessionPublisher: AnyPublisher<SessionState, Never> {
        session.statePublisher
    }
    
    // MARK: - Initialization
    
    private init() {}
    
    // MARK: - Configuration
    
    /// Configures the Vault SDK.
    ///
    /// This method must be called before using any other Vault functionality.
    /// It's safe to call this method multiple times - the last configuration will be used.
    ///
    /// - Parameter configuration: The configuration to use.
    public static func configure(_ configuration: Configuration) {
        shared.configuration = configuration
        shared.logger.debugMode = configuration.debugMode
        shared.logger.log("Vault SDK configured with tenant: \(configuration.tenantId)")
        
        // Pre-warm the API client
        _ = shared.apiClient
    }
    
    /// Configures the Vault SDK with convenience parameters.
    ///
    /// - Parameters:
    ///   - apiUrl: The API URL for Vault
    ///   - tenantId: Your tenant identifier
    ///   - apiKey: Optional API key for admin operations
    ///   - debugMode: Enable debug logging (default: false)
    public static func configure(
        apiUrl: String,
        tenantId: String,
        apiKey: String? = nil,
        debugMode: Bool = false
    ) {
        configure(Configuration(
            apiUrl: apiUrl,
            tenantId: tenantId,
            apiKey: apiKey,
            debugMode: debugMode
        ))
    }
    
    // MARK: - Utility
    
    /// Returns the current SDK version.
    public static var version: String {
        "1.0.0"
    }
    
    /// Checks if the SDK has been configured.
    public var isConfigured: Bool {
        configuration != nil
    }
    
    /// Resets the SDK state (useful for testing).
    public func reset() {
        Task {
            await session.signOut()
        }
        logger.log("Vault SDK reset")
    }
}

// MARK: - Session State

/// Represents the current session state.
public enum SessionState: Equatable {
    /// No user is signed in.
    case unauthenticated
    
    /// A user is signed in.
    case authenticated(VaultUser)
    
    /// The session is being refreshed.
    case refreshing
}
