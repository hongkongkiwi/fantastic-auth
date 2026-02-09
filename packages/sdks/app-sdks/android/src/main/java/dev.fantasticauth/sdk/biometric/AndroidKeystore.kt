package dev.vault.sdk.biometric

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import dev.vault.sdk.utils.VaultLogger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64

/**
 * Android Keystore utilities for hardware-backed cryptographic operations
 */
internal object AndroidKeystore {
    
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALGORITHM = KeyProperties.KEY_ALGORITHM_EC
    private const val SIGNATURE_ALGORITHM = "SHA256withECDSA"
    
    /**
     * Generate a key pair that requires biometric authentication
     * 
     * @param alias Key alias in the keystore
     * @param invalidatedByBiometricEnrollment Whether key should be invalidated on new biometric enrollment
     * @param requireBiometricAuth Whether to require biometric authentication for key use
     * @return Generated KeyPair
     */
    fun generateBiometricKey(
        alias: String,
        invalidatedByBiometricEnrollment: Boolean = true,
        requireBiometricAuth: Boolean = true
    ): KeyPair {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)
        
        // Delete existing key if present
        if (keyStore.containsAlias(alias)) {
            keyStore.deleteEntry(alias)
        }
        
        val keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, ANDROID_KEYSTORE)
        
        val builder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setKeySize(256)
            .setInvalidatedByBiometricEnrollment(invalidatedByBiometricEnrollment)
        
        if (requireBiometricAuth) {
            builder.setUserAuthenticationRequired(true)
            // Require authentication every time (0 = every use)
            builder.setUserAuthenticationValidityDurationSeconds(-1)
        }
        
        keyPairGenerator.initialize(builder.build())
        
        return keyPairGenerator.generateKeyPair().also {
            VaultLogger.i("Generated biometric key: $alias")
        }
    }
    
    /**
     * Generate a key pair without biometric requirement
     * Useful for device credential authentication
     * 
     * @param alias Key alias in the keystore
     * @return Generated KeyPair
     */
    fun generateKeyPair(alias: String): KeyPair {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)
        
        if (keyStore.containsAlias(alias)) {
            keyStore.deleteEntry(alias)
        }
        
        val keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, ANDROID_KEYSTORE)
        
        keyPairGenerator.initialize(
            KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setKeySize(256)
                .build()
        )
        
        return keyPairGenerator.generateKeyPair()
    }
    
    /**
     * Check if a key exists in the keystore
     * 
     * @param alias Key alias
     */
    fun hasKey(alias: String): Boolean {
        return try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)
            keyStore.containsAlias(alias)
        } catch (e: Exception) {
            VaultLogger.e("Error checking key existence: ${e.message}")
            false
        }
    }
    
    /**
     * Delete a key from the keystore
     * 
     * @param alias Key alias
     */
    fun deleteKey(alias: String) {
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)
            if (keyStore.containsAlias(alias)) {
                keyStore.deleteEntry(alias)
                VaultLogger.i("Deleted key: $alias")
            }
        } catch (e: Exception) {
            VaultLogger.e("Error deleting key: ${e.message}")
        }
    }
    
    /**
     * Get a Signature instance for signing with the specified key
     * This signature requires biometric authentication to use
     * 
     * @param alias Key alias
     * @return Signature instance
     * @throws KeyPermanentlyInvalidatedException if key was invalidated
     * @throws UserNotAuthenticatedException if user needs to authenticate
     */
    fun getSignatureInstance(alias: String): Signature {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)
        
        val privateKey = keyStore.getKey(alias, null)
            ?: throw IllegalStateException("Key not found: $alias")
        
        return Signature.getInstance(SIGNATURE_ALGORITHM).apply {
            initSign(privateKey)
        }
    }
    
    /**
     * Sign data with the specified key
     * Note: This will fail if biometric authentication hasn't been performed
     * 
     * @param alias Key alias
     * @param data Data to sign
     * @return Base64-encoded signature
     */
    fun signWithKey(alias: String, data: ByteArray): String {
        val signature = getSignatureInstance(alias)
        signature.update(data)
        return Base64.getEncoder().encodeToString(signature.sign())
    }
    
    /**
     * Verify a signature
     * 
     * @param alias Key alias
     * @param data Original data
     * @param signatureBase64 Base64-encoded signature
     * @return true if signature is valid
     */
    fun verifySignature(
        alias: String,
        data: ByteArray,
        signatureBase64: String
    ): Boolean {
        return try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)
            
            val certificate = keyStore.getCertificate(alias)
                ?: throw IllegalStateException("Certificate not found: $alias")
            
            val signature = Signature.getInstance(SIGNATURE_ALGORITHM)
            signature.initVerify(certificate.publicKey)
            signature.update(data)
            
            signature.verify(Base64.getDecoder().decode(signatureBase64))
        } catch (e: Exception) {
            VaultLogger.e("Signature verification failed: ${e.message}")
            false
        }
    }
    
    /**
     * Get public key as Base64 string
     * 
     * @param alias Key alias
     * @return Base64-encoded public key or null if key doesn't exist
     */
    fun getPublicKeyBase64(alias: String): String? {
        return try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)
            
            val certificate = keyStore.getCertificate(alias) ?: return null
            Base64.getEncoder().encodeToString(certificate.publicKey.encoded)
        } catch (e: Exception) {
            VaultLogger.e("Error getting public key: ${e.message}")
            null
        }
    }
    
    /**
     * Check if key was invalidated by biometric enrollment
     * 
     * @param alias Key alias
     * @return true if key is still valid
     */
    fun isKeyValid(alias: String): Boolean {
        return try {
            getSignatureInstance(alias)
            true
        } catch (e: KeyPermanentlyInvalidatedException) {
            VaultLogger.w("Key was invalidated: $alias")
            false
        } catch (e: Exception) {
            VaultLogger.e("Error checking key validity: ${e.message}")
            false
        }
    }
    
    /**
     * Generate AES key for encryption/decryption
     * 
     * @param alias Key alias
     * @param requireAuth Whether to require biometric authentication
     * @return true if key was generated successfully
     */
    fun generateAESKey(alias: String, requireAuth: Boolean = false): Boolean {
        return try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)
            
            if (keyStore.containsAlias(alias)) {
                keyStore.deleteEntry(alias)
            }
            
            val keyGenerator = javax.crypto.KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                ANDROID_KEYSTORE
            )
            
            val builder = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
            
            if (requireAuth) {
                builder.setUserAuthenticationRequired(true)
                builder.setUserAuthenticationValidityDurationSeconds(-1)
            }
            
            keyGenerator.init(builder.build())
            keyGenerator.generateKey()
            
            VaultLogger.i("Generated AES key: $alias")
            true
        } catch (e: Exception) {
            VaultLogger.e("Failed to generate AES key: ${e.message}")
            false
        }
    }
    
    /**
     * Get secret key for AES operations
     * 
     * @param alias Key alias
     * @return SecretKey or null if not found
     */
    fun getSecretKey(alias: String): javax.crypto.SecretKey? {
        return try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)
            keyStore.getKey(alias, null) as? javax.crypto.SecretKey
        } catch (e: Exception) {
            VaultLogger.e("Error getting secret key: ${e.message}")
            null
        }
    }
}
