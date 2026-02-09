import Foundation
import os.log

/// Internal logging utility for the Vault SDK.
///
/// This logger provides structured logging with different levels
/// and respects the debug mode configuration.
internal struct VaultLogger {
    
    // MARK: - Properties
    
    /// Whether debug logging is enabled.
    var debugMode: Bool = false
    
    /// The OS Log for Vault.
    private let logger = Logger(subsystem: "com.vault.sdk", category: "VaultSDK")
    
    // MARK: - Logging Methods
    
    /// Logs a debug message.
    ///
    /// - Parameter message: The message to log
    func log(_ message: String) {
        guard debugMode else { return }
        
        if #available(iOS 14.0, *) {
            logger.debug("\(message, privacy: .public)")
        } else {
            NSLog("[VaultSDK] DEBUG: \(message)")
        }
        
        #if DEBUG
        print("[VaultSDK] \(message)")
        #endif
    }
    
    /// Logs an info message.
    ///
    /// - Parameter message: The message to log
    func logInfo(_ message: String) {
        if #available(iOS 14.0, *) {
            logger.info("\(message, privacy: .public)")
        } else {
            NSLog("[VaultSDK] INFO: \(message)")
        }
    }
    
    /// Logs a warning message.
    ///
    /// - Parameter message: The message to log
    func logWarning(_ message: String) {
        if #available(iOS 14.0, *) {
            logger.warning("\(message, privacy: .public)")
        } else {
            NSLog("[VaultSDK] WARNING: \(message)")
        }
    }
    
    /// Logs an error message.
    ///
    /// - Parameter message: The message to log
    func logError(_ message: String) {
        if #available(iOS 14.0, *) {
            logger.error("\(message, privacy: .public)")
        } else {
            NSLog("[VaultSDK] ERROR: \(message)")
        }
    }
    
    /// Logs a network request.
    ///
    /// - Parameter request: The URL request
    func logRequest(_ request: URLRequest) {
        guard debugMode else { return }
        
        let method = request.httpMethod ?? "GET"
        let url = request.url?.absoluteString ?? "unknown"
        
        log("→ \(method) \(url)")
        
        if let headers = request.allHTTPHeaderFields {
            for (key, value) in headers where !key.lowercased().contains("authorization") {
                log("  \(key): \(value)")
            }
        }
        
        if let body = request.httpBody,
           let bodyString = String(data: body, encoding: .utf8) {
            // Redact sensitive fields
            let redacted = redactSensitiveData(bodyString)
            log("  Body: \(redacted)")
        }
    }
    
    /// Logs a network response.
    ///
    /// - Parameters:
    ///   - response: The URL response
    ///   - data: The response data
    func logResponse(_ response: URLResponse, data: Data) {
        guard debugMode else { return }
        
        guard let httpResponse = response as? HTTPURLResponse else {
            log("← Response: (non-HTTP)")
            return
        }
        
        let status = httpResponse.statusCode
        let statusEmoji = (200...299).contains(status) ? "✓" : "✗"
        log("← \(statusEmoji) HTTP \(status)")
        
        if let bodyString = String(data: data, encoding: .utf8) {
            // Truncate if too long
            let maxLength = 1000
            let truncated = bodyString.count > maxLength
                ? String(bodyString.prefix(maxLength)) + "... (truncated)"
                : bodyString
            log("  Body: \(truncated)")
        }
    }
    
    // MARK: - Private Methods
    
    /// Redacts sensitive data from JSON strings.
    ///
    /// - Parameter json: The JSON string
    /// - Returns: Redacted JSON string
    private func redactSensitiveData(_ json: String) -> String {
        let sensitiveKeys = ["password", "token", "secret", "key", "code", "credential"]
        var result = json
        
        for key in sensitiveKeys {
            // Match patterns like "password": "value" or "password":"value"
            let pattern = "\"\(key)\"\\s*:\\s*\"[^\"]*\""
            if let regex = try? NSRegularExpression(pattern: pattern, options: .caseInsensitive) {
                result = regex.stringByReplacingMatches(
                    in: result,
                    options: [],
                    range: NSRange(location: 0, length: result.utf16.count),
                    withTemplate: "\"\(key)\": \"***\""
                )
            }
        }
        
        return result
    }
}

// MARK: - Public Logging Interface

/// Log levels for the Vault SDK.
public enum VaultLogLevel: Int, Sendable {
    case debug = 0
    case info = 1
    case warning = 2
    case error = 3
    case none = 4
}

/// Public logging configuration.
public enum VaultLogging {
    /// The minimum log level to output.
    public static var minLevel: VaultLogLevel = .warning
    
    /// Custom log handler (optional).
    public static var customHandler: ((VaultLogLevel, String) -> Void)?
    
    /// Whether to include timestamps in logs.
    public static var includeTimestamps: Bool = false
    
    /// Internal logging function.
    internal static func log(_ level: VaultLogLevel, message: String) {
        guard level.rawValue >= minLevel.rawValue else { return }
        
        let prefix: String
        switch level {
        case .debug:
            prefix = "[VaultSDK] DEBUG"
        case .info:
            prefix = "[VaultSDK] INFO"
        case .warning:
            prefix = "[VaultSDK] WARNING"
        case .error:
            prefix = "[VaultSDK] ERROR"
        case .none:
            return
        }
        
        let timestamp = includeTimestamps
            ? "[\(ISO8601DateFormatter().string(from: Date()))] "
            : ""
        
        let formatted = "\(timestamp)\(prefix): \(message)"
        
        if let handler = customHandler {
            handler(level, formatted)
        } else {
            #if DEBUG
            print(formatted)
            #endif
        }
    }
}
