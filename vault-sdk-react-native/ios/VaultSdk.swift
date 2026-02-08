/**
 * VaultSdk Native Module for iOS
 * 
 * Optional native module for advanced iOS functionality.
 * Most features work with the JavaScript layer using existing libraries.
 */

import Foundation
import LocalAuthentication

@objc(VaultSdk)
class VaultSdk: NSObject {
  
  /// Check if biometric authentication is available
  @objc
  static func requiresMainQueueSetup() -> Bool {
    return false
  }
  
  /// Get available biometric type
  @objc
  func getBiometricType(_ resolve: @escaping RCTPromiseResolveBlock,
                        rejecter reject: @escaping RCTPromiseRejectBlock) {
    let context = LAContext()
    var error: NSError?
    
    if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
      switch context.biometryType {
      case .faceID:
        resolve("FaceID")
      case .touchID:
        resolve("TouchID")
      case .none:
        resolve("none")
      @unknown default:
        resolve("unknown")
      }
    } else {
      resolve("none")
    }
  }
  
  /// Authenticate with biometrics
  @objc
  func authenticate(_ prompt: String,
                   resolver resolve: @escaping RCTPromiseResolveBlock,
                   rejecter reject: @escaping RCTPromiseRejectBlock) {
    let context = LAContext()
    context.localizedFallbackTitle = "Use Passcode"
    
    var error: NSError?
    if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
      context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                            localizedReason: prompt) { success, error in
        DispatchQueue.main.async {
          if success {
            resolve(["success": true])
          } else {
            resolve([
              "success": false,
              "error": error?.localizedDescription ?? "Authentication failed"
            ])
          }
        }
      }
    } else {
      resolve([
        "success": false,
        "error": error?.localizedDescription ?? "Biometric authentication not available"
      ])
    }
  }
  
  /// Check if biometrics is enrolled
  @objc
  func isBiometricEnrolled(_ resolve: @escaping RCTPromiseResolveBlock,
                          rejecter reject: @escaping RCTPromiseRejectBlock) {
    let context = LAContext()
    var error: NSError?
    
    let canEvaluate = context.canEvaluatePolicy(
      .deviceOwnerAuthenticationWithBiometrics,
      error: &error
    )
    
    resolve(canEvaluate)
  }
}

// MARK: - RCTBridgeModule

extension VaultSdk: RCTBridgeModule {
  static func moduleName() -> String! {
    return "VaultSdk"
  }
}

// Required for RCTBridgeModule
protocol RCTBridgeModule {
  static func moduleName() -> String!
}

typealias RCTPromiseResolveBlock = (Any?) -> Void
typealias RCTPromiseRejectBlock = (String?, String?, Error?) -> Void
