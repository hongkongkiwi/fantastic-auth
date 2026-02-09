package com.vault.storage

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.vault.models.StorageException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Secure token storage implementation using Android Keystore
 * Provides hardware-backed encryption when available
 */
class KeystoreStorage(context: Context) : TokenStorage {

    private val masterKey: MasterKey
    private val encryptedPrefs: EncryptedSharedPreferences

    init {
        try {
            masterKey = MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .setUserAuthenticationRequired(false)
                .build()

            encryptedPrefs = EncryptedSharedPreferences.create(
                context,
                PREFS_FILE_NAME,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            ) as EncryptedSharedPreferences
        } catch (e: Exception) {
            // Fallback to regular SharedPreferences with manual encryption if EncryptedSharedPreferences fails
            throw StorageException.EncryptionFailed(e)
        }
    }

    override fun saveToken(key: String, token: String) {
        try {
            encryptedPrefs.edit().putString(key, token).apply()
        } catch (e: Exception) {
            throw StorageException.EncryptionFailed(e)
        }
    }

    override fun getToken(key: String): String? {
        return try {
            encryptedPrefs.getString(key, null)
        } catch (e: Exception) {
            null
        }
    }

    override fun deleteToken(key: String) {
        encryptedPrefs.edit().remove(key).apply()
    }

    override fun hasToken(key: String): Boolean {
        return encryptedPrefs.contains(key)
    }

    override fun clearAll() {
        encryptedPrefs.edit().clear().apply()
    }

    companion object {
        private const val PREFS_FILE_NAME = "vault_auth_secure_prefs"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "vault_auth_master_key"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val GCM_TAG_LENGTH = 128
        private const val GCM_IV_LENGTH = 12
    }
}

/**
 * Hardware-backed Keystore storage that requires biometric authentication
 * for accessing the encryption key
 */
class BiometricKeystoreStorage(context: Context) : TokenStorage {

    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    private val prefs: SharedPreferences = context.getSharedPreferences(
        BIOMETRIC_PREFS_FILE_NAME,
        Context.MODE_PRIVATE
    )

    init {
        if (!keyStore.containsAlias(BIOMETRIC_KEY_ALIAS)) {
            generateBiometricKey()
        }
    }

    private fun generateBiometricKey() {
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE
        )

        val builder = KeyGenParameterSpec.Builder(
            BIOMETRIC_KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)

        // Set authentication validity duration (0 means every operation requires auth)
        builder.setUserAuthenticationValidityDurationSeconds(0)

        keyGenerator.init(builder.build())
        keyGenerator.generateKey()
    }

    override fun saveToken(key: String, token: String) {
        // Note: This requires the user to be authenticated with biometric
        // before calling this method
        val cipher = Cipher.getInstance(TRANSFORMATION)
        val secretKey = keyStore.getKey(BIOMETRIC_KEY_ALIAS) as SecretKey
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)

        val iv = cipher.iv
        val encrypted = cipher.doFinal(token.toByteArray(Charsets.UTF_8))

        // Store IV + encrypted data
        val combined = ByteArray(iv.size + encrypted.size)
        System.arraycopy(iv, 0, combined, 0, iv.size)
        System.arraycopy(encrypted, 0, combined, iv.size, encrypted.size)

        val encoded = Base64.encodeToString(combined, Base64.DEFAULT)
        prefs.edit().putString(key, encoded).apply()
    }

    override fun getToken(key: String): String? {
        val encoded = prefs.getString(key, null) ?: return null

        val combined = Base64.decode(encoded, Base64.DEFAULT)
        val iv = combined.copyOfRange(0, GCM_IV_LENGTH)
        val encrypted = combined.copyOfRange(GCM_IV_LENGTH, combined.size)

        val cipher = Cipher.getInstance(TRANSFORMATION)
        val secretKey = keyStore.getKey(BIOMETRIC_KEY_ALIAS) as SecretKey
        cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(GCM_TAG_LENGTH, iv))

        return String(cipher.doFinal(encrypted), Charsets.UTF_8)
    }

    override fun deleteToken(key: String) {
        prefs.edit().remove(key).apply()
    }

    override fun hasToken(key: String): Boolean {
        return prefs.contains(key)
    }

    override fun clearAll() {
        prefs.edit().clear().apply()
    }

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val BIOMETRIC_KEY_ALIAS = "vault_auth_biometric_key"
        private const val BIOMETRIC_PREFS_FILE_NAME = "vault_auth_biometric_prefs"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val GCM_TAG_LENGTH = 128
        private const val GCM_IV_LENGTH = 12
    }
}

/**
 * Token storage factory
 */
object TokenStorageFactory {
    fun create(context: Context, requireBiometric: Boolean = false): TokenStorage {
        return if (requireBiometric) {
            BiometricKeystoreStorage(context)
        } else {
            KeystoreStorage(context)
        }
    }
}
