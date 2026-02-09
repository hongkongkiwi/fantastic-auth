import Foundation
import LocalAuthentication

// MARK: - BiometricError

public enum BiometricError: Error, LocalizedError, Equatable {
    case notAvailable
    case notEnrolled
    case invalidContext
    case authenticationFailed
    case userCancelled
    case userFallback
    case biometryLockout
    case systemError(Error)
    case unknown
    
    public var errorDescription: String? {
        switch self {
        case .notAvailable:
            return "Biometric authentication is not available on this device."
        case .notEnrolled:
            return "No biometric credentials are enrolled. Please set up Face ID or Touch ID in Settings."
        case .invalidContext:
            return "Invalid authentication context."
        case .authenticationFailed:
            return "Biometric authentication failed. Please try again."
        case .userCancelled:
            return "Authentication was cancelled."
        case .userFallback:
            return "User chose to use password fallback."
        case .biometryLockout:
            return "Biometric authentication is locked out due to too many failed attempts."
        case .systemError(let error):
            return "System error: \(error.localizedDescription)"
        case .unknown:
            return "An unknown biometric error occurred."
        }
    }
    
    /// Initialize from LAError
    init(from laError: LAError) {
        switch laError.code {
        case .biometryNotAvailable:
            self = .notAvailable
        case .biometryNotEnrolled:
            self = .notEnrolled
        case .invalidContext:
            self = .invalidContext
        case .authenticationFailed:
            self = .authenticationFailed
        case .userCancel:
            self = .userCancelled
        case .userFallback:
            self = .userFallback
        case .biometryLockout:
            self = .biometryLockout
        default:
            self = .systemError(laError)
        }
    }
    
    /// Initialize from NSError
    init(from error: NSError) {
        if let laError = error as? LAError {
            self = BiometricError(from: laError)
        } else {
            self = .systemError(error)
        }
    }
    
    public static func == (lhs: BiometricError, rhs: BiometricError) -> Bool {
        switch (lhs, rhs) {
        case (.notAvailable, .notAvailable),
             (.notEnrolled, .notEnrolled),
             (.invalidContext, .invalidContext),
             (.authenticationFailed, .authenticationFailed),
             (.userCancelled, .userCancelled),
             (.userFallback, .userFallback),
             (.biometryLockout, .biometryLockout),
             (.unknown, .unknown):
            return true
        case (.systemError(let lhsError), .systemError(let rhsError)):
            return lhsError.localizedDescription == rhsError.localizedDescription
        default:
            return false
        }
    }
}

// MARK: - BiometricType

public enum BiometricType: String, CaseIterable {
    case none
    case touchID
    case faceID
    case opticID
    
    public var displayName: String {
        switch self {
        case .none:
            return "None"
        case .touchID:
            return "Touch ID"
        case .faceID:
            return "Face ID"
        case .opticID:
            return "Optic ID"
        }
    }
    
    public var iconName: String {
        switch self {
        case .none:
            return "lock"
        case .touchID:
            return "touchid"
        case .faceID:
            return "faceid"
        case .opticID:
            return "eye"
        }
    }
    
    public var systemImageName: String {
        switch self {
        case .none:
            return "lock.fill"
        case .touchID:
            if #available(iOS 15.0, *) {
                return "touchid"
            } else {
                return "fingerprint"
            }
        case .faceID:
            if #available(iOS 15.0, *) {
                return "faceid"
            } else {
                return "person.fill"
            }
        case .opticID:
            return "eye.fill"
        }
    }
}

// MARK: - BiometricContext

public protocol BiometricContext {
    var biometricType: BiometricType { get }
    var isAvailable: Bool { get }
    var isEnrolled: Bool { get }
    func canEvaluatePolicy(_ policy: LAPolicy, error: NSErrorPointer) -> Bool
    func evaluatePolicy(_ policy: LAPolicy, localizedReason: String, reply: @escaping (Bool, Error?) -> Void)
}

// MARK: - LABiometricContext

class LABiometricContext: BiometricContext {
    private let context: LAContext
    
    init(context: LAContext = LAContext()) {
        self.context = context
    }
    
    var biometricType: BiometricType {
        // Touch ID support was introduced before Face ID
        // We need to check the biometryType property
        if #available(iOS 11.0, *) {
            switch context.biometryType {
            case .faceID:
                return .faceID
            case .touchID:
                return .touchID
            case .opticID:
                if #available(iOS 17.0, *) {
                    return .opticID
                } else {
                    return .none
                }
            default:
                return .none
            }
        } else {
            // Before iOS 11, only Touch ID was available
            let canEvaluate = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
            return canEvaluate ? .touchID : .none
        }
    }
    
    var isAvailable: Bool {
        return context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
    }
    
    var isEnrolled: Bool {
        var error: NSError?
        let canEvaluate = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
        
        if let laError = error as? LAError {
            return laError.code != .biometryNotEnrolled && canEvaluate
        }
        
        return canEvaluate
    }
    
    func canEvaluatePolicy(_ policy: LAPolicy, error: NSErrorPointer) -> Bool {
        return context.canEvaluatePolicy(policy, error: error)
    }
    
    func evaluatePolicy(_ policy: LAPolicy, localizedReason: String, reply: @escaping (Bool, Error?) -> Void) {
        context.evaluatePolicy(policy, localizedReason: localizedReason, reply: reply)
    }
}
