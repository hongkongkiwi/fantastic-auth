import Foundation
import CryptoKit
import CommonCrypto

/// Cryptographic utilities for the Vault SDK.
///
/// This class provides helper methods for common cryptographic operations
/// including hashing, encryption, and random generation.
public enum VaultCrypto {
    
    // MARK: - Hashing
    
    /// Computes the SHA-256 hash of data.
    ///
    /// - Parameter data: The data to hash
    /// - Returns: The SHA-256 hash
    public static func sha256(_ data: Data) -> Data {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes { buffer in
            _ = CC_SHA256(buffer.baseAddress, CC_LONG(data.count), &hash)
        }
        return Data(hash)
    }
    
    /// Computes the SHA-256 hash of a string.
    ///
    /// - Parameter string: The string to hash
    /// - Returns: The SHA-256 hash as a hex string
    public static func sha256(_ string: String) -> String {
        guard let data = string.data(using: .utf8) else {
            return ""
        }
        return sha256(data).hexEncodedString()
    }
    
    /// Computes the HMAC-SHA256 of data.
    ///
    /// - Parameters:
    ///   - data: The data to sign
    ///   - key: The secret key
    /// - Returns: The HMAC
    public static func hmacSHA256(_ data: Data, key: Data) -> Data {
        var mac = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        key.withUnsafeBytes { keyBytes in
            data.withUnsafeBytes { dataBytes in
                CCHmac(
                    CCHmacAlgorithm(kCCHmacAlgSHA256),
                    keyBytes.baseAddress,
                    key.count,
                    dataBytes.baseAddress,
                    data.count,
                    &mac
                )
            }
        }
        return Data(mac)
    }
    
    /// Computes the HMAC-SHA256 of a string.
    ///
    /// - Parameters:
    ///   - string: The string to sign
    ///   - key: The secret key
    /// - Returns: The HMAC as a base64 string
    public static func hmacSHA256(_ string: String, key: String) -> String {
        guard let data = string.data(using: .utf8),
              let keyData = key.data(using: .utf8) else {
            return ""
        }
        return hmacSHA256(data, key: keyData).base64EncodedString()
    }
    
    // MARK: - Random Generation
    
    /// Generates cryptographically secure random bytes.
    ///
    /// - Parameter count: The number of bytes to generate
    /// - Returns: Random bytes
    /// - Throws: `VaultError` if generation fails
    public static func randomBytes(count: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        
        guard status == errSecSuccess else {
            throw VaultError.keyGenerationFailed("Failed to generate random bytes: \(status)")
        }
        
        return Data(bytes)
    }
    
    /// Generates a cryptographically secure random string.
    ///
    /// - Parameter length: The length of the string
    /// - Returns: A random alphanumeric string
    public static func randomString(length: Int) -> String {
        let letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        return String((0..<length).compactMap { _ in
            letters.randomElement()
        })
    }
    
    /// Generates a random alphanumeric string with a given character set.
    ///
    /// - Parameters:
    ///   - length: The length of the string
    ///   - characters: The allowed characters
    /// - Returns: A random string
    public static func randomString(length: Int, characters: String) -> String {
        var result = ""
        var rng = SystemRandomNumberGenerator()
        
        for _ in 0..<length {
            let index = characters.index(
                characters.startIndex,
                offsetBy: Int.random(in: 0..<characters.count, using: &rng)
            )
            result.append(characters[index])
        }
        
        return result
    }
    
    /// Generates a UUID v4 string.
    ///
    /// - Returns: A UUID string
    public static func generateUUID() -> String {
        UUID().uuidString
    }
    
    // MARK: - Base64
    
    /// Encodes data to a Base64 string.
    ///
    /// - Parameter data: The data to encode
    /// - Returns: Base64-encoded string
    public static func base64Encode(_ data: Data) -> String {
        data.base64EncodedString()
    }
    
    /// Decodes a Base64 string to data.
    ///
    /// - Parameter string: The Base64 string
    /// - Returns: Decoded data, or `nil` if invalid
    public static func base64Decode(_ string: String) -> Data? {
        Data(base64Encoded: string)
    }
    
    /// Encodes data to a URL-safe Base64 string.
    ///
    /// - Parameter data: The data to encode
    /// - Returns: URL-safe Base64 string
    public static func base64URLEncode(_ data: Data) -> String {
        base64Encode(data)
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
    
    /// Decodes a URL-safe Base64 string to data.
    ///
    /// - Parameter string: The URL-safe Base64 string
    /// - Returns: Decoded data, or `nil` if invalid
    public static func base64URLDecode(_ string: String) -> Data? {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        
        // Add padding
        while base64.count % 4 != 0 {
            base64 += "="
        }
        
        return Data(base64Encoded: base64)
    }
    
    // MARK: - Password Security
    
    /// Checks password strength.
    ///
    /// - Parameter password: The password to check
    /// - Returns: A score from 0-4 (0 = very weak, 4 = very strong)
    public static func passwordStrength(_ password: String) -> Int {
        var score = 0
        
        // Length
        if password.count >= 8 { score += 1 }
        if password.count >= 12 { score += 1 }
        
        // Complexity
        let hasUppercase = password.range(of: "[A-Z]", options: .regularExpression) != nil
        let hasLowercase = password.range(of: "[a-z]", options: .regularExpression) != nil
        let hasNumber = password.range(of: "[0-9]", options: .regularExpression) != nil
        let hasSpecial = password.range(of: "[^A-Za-z0-9]", options: .regularExpression) != nil
        
        let complexity = [hasUppercase, hasLowercase, hasNumber, hasSpecial].filter { $0 }.count
        if complexity >= 3 { score += 1 }
        if complexity == 4 { score += 1 }
        
        return min(score, 4)
    }
    
    /// Generates a secure password.
    ///
    /// - Parameters:
    ///   - length: The length of the password (default: 16)
    ///   - includeSpecial: Whether to include special characters
    /// - Returns: A secure random password
    public static func generatePassword(length: Int = 16, includeSpecial: Bool = true) -> String {
        let letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        let numbers = "0123456789"
        let special = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        var characters = letters + numbers
        if includeSpecial {
            characters += special
        }
        
        // Ensure at least one of each type
        var password = ""
        password.append(letters.randomElement()!)
        password.append(letters.uppercased().randomElement()!)
        password.append(numbers.randomElement()!)
        if includeSpecial {
            password.append(special.randomElement()!)
        }
        
        // Fill the rest
        for _ in password.count..<length {
            password.append(characters.randomElement()!)
        }
        
        // Shuffle
        return String(password.shuffled())
    }
    
    // MARK: - Key Derivation
    
    /// Derives a key using PBKDF2.
    ///
    /// - Parameters:
    ///   - password: The password
    ///   - salt: The salt
    ///   - iterations: Number of iterations (default: 100000)
    ///   - keyLength: Desired key length in bytes (default: 32)
    /// - Returns: Derived key
    public static func pbkdf2(
        password: String,
        salt: Data,
        iterations: Int = 100000,
        keyLength: Int = 32
    ) -> Data? {
        guard let passwordData = password.data(using: .utf8) else {
            return nil
        }
        
        var derivedKey = [UInt8](repeating: 0, count: keyLength)
        
        let result = CCKeyDerivationPBKDF(
            CCPBKDFAlgorithm(kCCPBKDF2),
            password,
            passwordData.count,
            [UInt8](salt),
            salt.count,
            CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
            UInt32(iterations),
            &derivedKey,
            keyLength
        )
        
        guard result == kCCSuccess else {
            return nil
        }
        
        return Data(derivedKey)
    }
}

// MARK: - Data Extensions

extension Data {
    /// Returns the data as a hexadecimal string.
    var hexEncodedString: String {
        map { String(format: "%02hhx", $0) }.joined()
    }
    
    /// Initializes data from a hexadecimal string.
    ///
    /// - Parameter hex: The hexadecimal string
    init?(hex: String) {
        let length = hex.count / 2
        var data = Data(capacity: length)
        
        for i in 0..<length {
            let start = hex.index(hex.startIndex, offsetBy: i * 2)
            let end = hex.index(start, offsetBy: 2)
            let byteString = hex[start..<end]
            
            if var num = UInt8(byteString, radix: 16) {
                data.append(&num, count: 1)
            } else {
                return nil
            }
        }
        
        self = data
    }
}

// MARK: - String Extensions

extension String {
    /// Returns the SHA-256 hash of the string.
    var sha256: String {
        VaultCrypto.sha256(self)
    }
    
    /// Computes HMAC-SHA256 with the given key.
    ///
    /// - Parameter key: The secret key
    /// - Returns: The HMAC as base64
    func hmacSHA256(key: String) -> String {
        VaultCrypto.hmacSHA256(self, key: key)
    }
    
    /// Returns the base64-encoded data.
    var base64Encoded: String? {
        data(using: .utf8)?.base64EncodedString()
    }
    
    /// Returns the base64-decoded string.
    var base64Decoded: String? {
        guard let data = Data(base64Encoded: self) else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }
}
