package com.vault.storage

/**
 * Interface for secure token storage
 */
interface TokenStorage {
    /**
     * Save a token to secure storage
     * @param key The key to store the token under
     * @param token The token to store
     */
    fun saveToken(key: String, token: String)

    /**
     * Retrieve a token from secure storage
     * @param key The key the token was stored under
     * @return The stored token, or null if not found
     */
    fun getToken(key: String): String?

    /**
     * Delete a token from secure storage
     * @param key The key of the token to delete
     */
    fun deleteToken(key: String)

    /**
     * Check if a token exists in storage
     * @param key The key to check
     * @return true if the token exists
     */
    fun hasToken(key: String): Boolean

    /**
     * Clear all tokens from storage
     */
    fun clearAll()

    companion object {
        const val KEY_ACCESS_TOKEN = "access_token"
        const val KEY_REFRESH_TOKEN = "refresh_token"
        const val KEY_BIOMETRIC_TOKEN = "biometric_token"
        const val KEY_USER_DATA = "user_data"
        const val KEY_SESSION_DATA = "session_data"
    }
}

/**
 * In-memory token storage implementation (for testing)
 */
class InMemoryTokenStorage : TokenStorage {
    private val storage = mutableMapOf<String, String>()

    override fun saveToken(key: String, token: String) {
        storage[key] = token
    }

    override fun getToken(key: String): String? {
        return storage[key]
    }

    override fun deleteToken(key: String) {
        storage.remove(key)
    }

    override fun hasToken(key: String): Boolean {
        return storage.containsKey(key)
    }

    override fun clearAll() {
        storage.clear()
    }
}
