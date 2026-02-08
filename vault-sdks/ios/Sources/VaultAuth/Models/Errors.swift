import Foundation

// MARK: - VaultAuthError

public enum VaultAuthError: Error, LocalizedError {
    // Configuration errors
    case notConfigured
    case invalidConfiguration(String)
    
    // Authentication errors
    case invalidCredentials
    case sessionExpired
    case userNotFound
    case accountLocked
    case accountNotVerified
    
    // Token errors
    case tokenNotFound
    case tokenInvalid
    case tokenRefreshFailed
    
    // Network errors
    case networkError(Error)
    case serverError(Int, String?)
    case decodingError(Error)
    
    // Biometric errors
    case biometricNotAvailable
    case biometricNotEnrolled
    case biometricFailed
    case biometricCancelled
    
    // MFA errors
    case mfaRequired
    case mfaInvalidCode
    case mfaSetupFailed
    
    // OAuth errors
    case oauthCancelled
    case oauthFailed(String)
    
    // Organization errors
    case organizationNotFound
    case organizationSwitchFailed
    
    // General errors
    case unknown(String)
    
    public var errorDescription: String? {
        switch self {
        case .notConfigured:
            return "VaultAuth has not been configured. Call configure() first."
        case .invalidConfiguration(let reason):
            return "Invalid configuration: \(reason)"
        case .invalidCredentials:
            return "Invalid email or password."
        case .sessionExpired:
            return "Your session has expired. Please log in again."
        case .userNotFound:
            return "User not found."
        case .accountLocked:
            return "Account is locked. Please contact support."
        case .accountNotVerified:
            return "Account is not verified. Please check your email."
        case .tokenNotFound:
            return "Authentication token not found."
        case .tokenInvalid:
            return "Authentication token is invalid."
        case .tokenRefreshFailed:
            return "Failed to refresh session."
        case .networkError(let error):
            return "Network error: \(error.localizedDescription)"
        case .serverError(let code, let message):
            return "Server error (\(code)): \(message ?? "Unknown error")"
        case .decodingError(let error):
            return "Failed to decode response: \(error.localizedDescription)"
        case .biometricNotAvailable:
            return "Biometric authentication is not available on this device."
        case .biometricNotEnrolled:
            return "No biometric credentials are enrolled."
        case .biometricFailed:
            return "Biometric authentication failed."
        case .biometricCancelled:
            return "Biometric authentication was cancelled."
        case .mfaRequired:
            return "Multi-factor authentication is required."
        case .mfaInvalidCode:
            return "Invalid MFA code. Please try again."
        case .mfaSetupFailed:
            return "Failed to set up MFA."
        case .oauthCancelled:
            return "OAuth authentication was cancelled."
        case .oauthFailed(let reason):
            return "OAuth authentication failed: \(reason)"
        case .organizationNotFound:
            return "Organization not found."
        case .organizationSwitchFailed:
            return "Failed to switch organization."
        case .unknown(let message):
            return "Unknown error: \(message)"
        }
    }
    
    public var isRetryable: Bool {
        switch self {
        case .networkError, .serverError:
            return true
        default:
            return false
        }
    }
}

// MARK: - APIErrorResponse

struct APIErrorResponse: Codable {
    let error: String
    let message: String?
    let code: String?
}

// MARK: - KeychainError

enum KeychainError: Error {
    case itemNotFound
    case duplicateItem
    case invalidStatus(OSStatus)
    case conversionFailed
    
    var localizedDescription: String {
        switch self {
        case .itemNotFound:
            return "Keychain item not found"
        case .duplicateItem:
            return "Keychain item already exists"
        case .invalidStatus(let status):
            return "Keychain error: \(status)"
        case .conversionFailed:
            return "Failed to convert keychain data"
        }
    }
}
