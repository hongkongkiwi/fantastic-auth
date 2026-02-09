import Flutter
import UIKit
import LocalAuthentication

public class VaultSdkPlugin: NSObject, FlutterPlugin {
  public static func register(with registrar: FlutterPluginRegistrar) {
    let channel = FlutterMethodChannel(name: "vault_sdk", binaryMessenger: registrar.messenger())
    let instance = VaultSdkPlugin()
    registrar.addMethodCallDelegate(instance, channel: channel)
  }

  public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    switch call.method {
    case "getPlatformVersion":
      result("iOS " + UIDevice.current.systemVersion)
    case "isBiometricAvailable":
      isBiometricAvailable(result: result)
    case "getBiometricType":
      getBiometricType(result: result)
    case "authenticateWithBiometrics":
      let args = call.arguments as? [String: Any]
      let reason = args?["reason"] as? String ?? "Authenticate"
      authenticateWithBiometrics(reason: reason, result: result)
    default:
      result(FlutterMethodNotImplemented)
    }
  }

  private func isBiometricAvailable(result: @escaping FlutterResult) {
    let context = LAContext()
    var error: NSError?
    
    let canEvaluate = context.canEvaluatePolicy(
      .deviceOwnerAuthenticationWithBiometrics,
      error: &error
    )
    
    result(canEvaluate)
  }

  private func getBiometricType(result: @escaping FlutterResult) {
    let context = LAContext()
    
    if #available(iOS 11.0, *) {
      switch context.biometryType {
      case .faceID:
        result("faceID")
      case .touchID:
        result("touchID")
      case .none:
        result("none")
      default:
        result("unknown")
      }
    } else {
      result("touchID")
    }
  }

  private func authenticateWithBiometrics(reason: String, result: @escaping FlutterResult) {
    let context = LAContext()
    var error: NSError?
    
    let canEvaluate = context.canEvaluatePolicy(
      .deviceOwnerAuthenticationWithBiometrics,
      error: &error
    )
    
    guard canEvaluate else {
      result(FlutterError(
        code: "BIOMETRIC_NOT_AVAILABLE",
        message: "Biometric authentication is not available",
        details: nil
      ))
      return
    }
    
    context.evaluatePolicy(
      .deviceOwnerAuthenticationWithBiometrics,
      localizedReason: reason
    ) { success, error in
      DispatchQueue.main.async {
        if let error = error {
          result(FlutterError(
            code: "AUTHENTICATION_ERROR",
            message: error.localizedDescription,
            details: nil
          ))
        } else {
          result(success)
        }
      }
    }
  }
}
