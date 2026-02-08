import Foundation

/// Errors that can occur when using the Vault SDK.
public enum VaultError: Error, LocalizedError, Equatable {
    /// The SDK has not been configured.
    case notConfigured
    
    /// The URL is invalid.
    case invalidURL
    
    /// The response from the server was invalid.
    case invalidResponse
    
    /// Failed to decode the response.
    case decodingFailed(Error)
    
    /// A network error occurred.
    case networkError(Error)
    
    /// The user is not authorized.
    case unauthorized
    
    /// The operation is forbidden.
    case forbidden
    
    /// The requested resource was not found.
    case notFound
    
    /// There was a conflict with the current state.
    case conflict(String)
    
    /// Validation failed for the request.
    case validationFailed([String: [String]])
    
    /// The rate limit has been exceeded.
    case rateLimited
    
    /// A server error occurred.
    case serverError(Int)
    
    /// An unknown error occurred.
    case unknown(Int)
    
    /// Biometric authentication is not available.
    case biometricNotAvailable
    
    /// Biometric authentication failed.
    case biometricFailed(String)
    
    /// The key was not found in the keychain.
    case keyNotFound
    
    /// Failed to generate a secure key.
    case keyGenerationFailed(String)
    
    /// The session has expired.
    case sessionExpired
    
    /// No active organization is selected.
    case noActiveOrganization
    
    /// OAuth authentication failed.
    case oauthFailed(String)
    
    /// The user cancelled the operation.
    case userCancelled
    
    /// The operation is not supported.
    case notSupported
    
    public var errorDescription: String? {
        switch self {
        case .notConfigured:
            return "The Vault SDK has not been configured. Call Vault.configure() first."
        case .invalidURL:
            return "The URL is invalid."
        case .invalidResponse:
            return "The response from the server was invalid."
        case .decodingFailed(let error):
            return "Failed to decode the response: \(error.localizedDescription)"
        case .networkError(let error):
            return "A network error occurred: \(error.localizedDescription)"
        case .unauthorized:
            return "You are not authorized to perform this action. Please sign in again."
        case .forbidden:
            return "This action is forbidden."
        case .notFound:
            return "The requested resource was not found."
        case .conflict(let message):
            return "Conflict: \(message)"
        case .validationFailed(let errors):
            let errorMessages = errors.flatMap { $0.value }.joined(separator: ", ")
            return "Validation failed: \(errorMessages)"
        case .rateLimited:
            return "Rate limit exceeded. Please try again later."
        case .serverError(let code):
            return "A server error occurred (HTTP \(code)). Please try again later."
        case .unknown(let code):
            return "An unknown error occurred (HTTP \(code))."
        case .biometricNotAvailable:
            return "Biometric authentication is not available on this device."
        case .biometricFailed(let reason):
            return "Biometric authentication failed: \(reason)"
        case .keyNotFound:
            return "The required key was not found."
        case .keyGenerationFailed(let reason):
            return "Failed to generate secure key: \(reason)"
        case .sessionExpired:
            return "Your session has expired. Please sign in again."
        case .noActiveOrganization:
            return "No active organization is selected."
        case .oauthFailed(let reason):
            return "OAuth authentication failed: \(reason)"
        case .userCancelled:
            return "The operation was cancelled by the user."
        case .notSupported:
            return "This operation is not supported."
        }
    }
    
    public var isRetryable: Bool {
        switch self {
        case .networkError, .rateLimited, .serverError:
            return true
        default:
            return false
        }
    }
    
    public static func == (lhs: VaultError, rhs: VaultError) -> Bool {
        switch (lhs, rhs) {
        case (.notConfigured, .notConfigured),
             (.invalidURL, .invalidURL),
             (.invalidResponse, .invalidResponse),
             (.unauthorized, .unauthorized),
             (.forbidden, .forbidden),
             (.notFound, .notFound),
             (.rateLimited, .rateLimited),
             (.biometricNotAvailable, .biometricNotAvailable),
             (.keyNotFound, .keyNotFound),
             (.sessionExpired, .sessionExpired),
             (.noActiveOrganization, .noActiveOrganization),
             (.userCancelled, .userCancelled),
             (.notSupported, .notSupported):
            return true
        case (.conflict(let lhsMsg), .conflict(let rhsMsg)):
            return lhsMsg == rhsMsg
        case (.biometricFailed(let lhsMsg), .biometricFailed(let rhsMsg)):
            return lhsMsg == rhsMsg
        case (.keyGenerationFailed(let lhsMsg), .keyGenerationFailed(let rhsMsg)):
            return lhsMsg == rhsMsg
        case (.oauthFailed(let lhsMsg), .oauthFailed(let rhsMsg)):
            return lhsMsg == rhsMsg
        case (.serverError(let lhsCode), .serverError(let rhsCode)),
             (.unknown(let lhsCode), .unknown(let rhsCode)):
            return lhsCode == rhsCode
        default:
            return false
        }
    }
}

// MARK: - Field Validation Error

/// Errors related to field validation.
public enum ValidationError: Error, LocalizedError {
    case invalidEmail
    case invalidPassword(String)
    case requiredField(String)
    case tooShort(field: String, minLength: Int)
    case tooLong(field: String, maxLength: Int)
    
    public var errorDescription: String? {
        switch self {
        case .invalidEmail:
            return "Please enter a valid email address."
        case .invalidPassword(let reason):
            return "Invalid password: \(reason)"
        case .requiredField(let field):
            return "\(field) is required."
        case .tooShort(let field, let minLength):
            return "\(field) must be at least \(minLength) characters."
        case .tooLong(let field, let maxLength):
            return "\(field) must be no more than \(maxLength) characters."
        }
    }
}
