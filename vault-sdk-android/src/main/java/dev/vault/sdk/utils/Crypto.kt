package dev.vault.sdk.utils

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Cryptographic utilities for Vault SDK
 */
internal object Crypto {
    
    private const val AES_ALGORITHM = "AES/GCM/NoPadding"
    private const val AES_KEY_SIZE = 256
    private const val GCM_IV_LENGTH = 12
    private const val GCM_TAG_LENGTH = 128
    
    private const val HMAC_ALGORITHM = "HmacSHA256"
    
    /**
     * Generate a cryptographically secure random string
     * 
     * @param length Length in bytes (before base64 encoding)
     * @return Base64-encoded random string
     */
    fun generateSecureRandom(length: Int = 32): String {
        val bytes = ByteArray(length)
        SecureRandom().nextBytes(bytes)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }
    
    /**
     * Generate a random UUID
     */
    fun generateUUID(): String {
        return java.util.UUID.randomUUID().toString()
    }
    
    /**
     * Generate PKCE code verifier
     */
    fun generateCodeVerifier(): String {
        return generateSecureRandom(32)
    }
    
    /**
     * Generate PKCE code challenge from verifier
     * 
     * @param verifier Code verifier
     * @return Base64-encoded SHA256 hash
     */
    fun generateCodeChallenge(verifier: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(verifier.toByteArray(Charsets.UTF_8))
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash)
    }
    
    /**
     * Generate SHA-256 hash
     * 
     * @param input String to hash
     * @return Hex-encoded hash
     */
    fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(input.toByteArray(Charsets.UTF_8))
        return hashToHex(hash)
    }
    
    /**
     * Generate SHA-512 hash
     * 
     * @param input String to hash
     * @return Hex-encoded hash
     */
    fun sha512(input: String): String {
        val digest = MessageDigest.getInstance("SHA-512")
        val hash = digest.digest(input.toByteArray(Charsets.UTF_8))
        return hashToHex(hash)
    }
    
    /**
     * Encrypt data using AES-256-GCM
     * 
     * @param plaintext Data to encrypt
     * @param key Encryption key (must be 32 bytes)
     * @return Encrypted data with IV prepended
     */
    fun aesEncrypt(plaintext: ByteArray, key: ByteArray): ByteArray {
        require(key.size == 32) { "Key must be 32 bytes (256 bits)" }
        
        val iv = ByteArray(GCM_IV_LENGTH)
        SecureRandom().nextBytes(iv)
        
        val cipher = Cipher.getInstance(AES_ALGORITHM)
        val spec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), spec)
        
        val ciphertext = cipher.doFinal(plaintext)
        
        // Prepend IV to ciphertext
        return iv + ciphertext
    }
    
    /**
     * Decrypt data using AES-256-GCM
     * 
     * @param encryptedData Data with IV prepended
     * @param key Encryption key (must be 32 bytes)
     * @return Decrypted plaintext
     */
    fun aesDecrypt(encryptedData: ByteArray, key: ByteArray): ByteArray {
        require(key.size == 32) { "Key must be 32 bytes (256 bits)" }
        require(encryptedData.size > GCM_IV_LENGTH) { "Invalid encrypted data" }
        
        val iv = encryptedData.sliceArray(0 until GCM_IV_LENGTH)
        val ciphertext = encryptedData.sliceArray(GCM_IV_LENGTH until encryptedData.size)
        
        val cipher = Cipher.getInstance(AES_ALGORITHM)
        val spec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), spec)
        
        return cipher.doFinal(ciphertext)
    }
    
    /**
     * Generate HMAC-SHA256
     * 
     * @param data Data to sign
     * @param key Secret key
     * @return HMAC value
     */
    fun hmacSha256(data: String, key: String): ByteArray {
        val mac = Mac.getInstance(HMAC_ALGORITHM)
        mac.init(SecretKeySpec(key.toByteArray(Charsets.UTF_8), HMAC_ALGORITHM))
        return mac.doFinal(data.toByteArray(Charsets.UTF_8))
    }
    
    /**
     * Generate HMAC-SHA256 as hex string
     * 
     * @param data Data to sign
     * @param key Secret key
     * @return Hex-encoded HMAC
     */
    fun hmacSha256Hex(data: String, key: String): String {
        return hashToHex(hmacSha256(data, key))
    }
    
    /**
     * Constant-time comparison to prevent timing attacks
     * 
     * @param a First byte array
     * @param b Second byte array
     * @return true if arrays are equal
     */
    fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var result = 0
        for (i in a.indices) {
            result = result or (a[i].toInt() xor b[i].toInt())
        }
        return result == 0
    }
    
    /**
     * Constant-time string comparison
     */
    fun constantTimeEquals(a: String, b: String): Boolean {
        return constantTimeEquals(
            a.toByteArray(Charsets.UTF_8),
            b.toByteArray(Charsets.UTF_8)
        )
    }
    
    /**
     * Derive key from password using PBKDF2
     * 
     * @param password Password
     * @param salt Salt
     * @param iterations Number of iterations
     * @param keyLength Desired key length in bits
     * @return Derived key
     */
    fun deriveKey(
        password: String,
        salt: ByteArray,
        iterations: Int = 100000,
        keyLength: Int = 256
    ): ByteArray {
        return javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            .generateSecret(
                javax.crypto.spec.PBEKeySpec(
                    password.toCharArray(),
                    salt,
                    iterations,
                    keyLength
                )
            )
            .encoded
    }
    
    /**
     * Generate random bytes
     * 
     * @param length Number of bytes
     * @return Random bytes
     */
    fun randomBytes(length: Int): ByteArray {
        return ByteArray(length).apply {
            SecureRandom().nextBytes(this)
        }
    }
    
    /**
     * Encode bytes to Base64
     */
    fun base64Encode(bytes: ByteArray): String {
        return Base64.getEncoder().encodeToString(bytes)
    }
    
    /**
     * Decode Base64 string
     */
    fun base64Decode(base64: String): ByteArray {
        return Base64.getDecoder().decode(base64)
    }
    
    /**
     * Encode bytes to URL-safe Base64
     */
    fun base64UrlEncode(bytes: ByteArray): String {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }
    
    /**
     * Decode URL-safe Base64 string
     */
    fun base64UrlDecode(base64: String): ByteArray {
        return Base64.getUrlDecoder().decode(base64)
    }
    
    /**
     * Encode bytes to hex string
     */
    fun hashToHex(bytes: ByteArray): String {
        val hexChars = "0123456789abcdef"
        val result = StringBuilder(bytes.size * 2)
        for (byte in bytes) {
            val v = byte.toInt() and 0xFF
            result.append(hexChars[v ushr 4])
            result.append(hexChars[v and 0x0F])
        }
        return result.toString()
    }
    
    /**
     * Decode hex string to bytes
     */
    fun hexToBytes(hex: String): ByteArray {
        require(hex.length % 2 == 0) { "Hex string must have even length" }
        return ByteArray(hex.length / 2) { i ->
            hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }
}

/**
 * Extension functions for crypto operations
 */
fun String.sha256(): String = Crypto.sha256(this)
fun String.sha512(): String = Crypto.sha512(this)
fun String.hmacSha256(key: String): String = Crypto.hmacSha256Hex(this, key)
fun ByteArray.toBase64(): String = Crypto.base64Encode(this)
fun ByteArray.toHex(): String = Crypto.hashToHex(this)
fun String.fromBase64(): ByteArray = Crypto.base64Decode(this)
fun String.fromHex(): ByteArray = Crypto.hexToBytes(this)
