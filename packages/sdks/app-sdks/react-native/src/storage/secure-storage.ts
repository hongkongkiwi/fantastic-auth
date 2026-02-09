/**
 * Secure Storage Module
 * 
 * Provides secure storage using iOS Keychain and Android Keystore.
 * Falls back to AsyncStorage for non-sensitive data.
 */

import { Platform } from 'react-native';
import { SecureStorageOptions, SecureStorageItem } from '../types';

// Storage keys
const VAULT_SERVICE = 'com.vault.secure';
const TOKEN_KEY = 'fantasticauth_session_token';
const REFRESH_TOKEN_KEY = 'fantasticauth_refresh_token';
const USER_DATA_KEY = 'fantasticauth_user_data';
const ORG_DATA_KEY = 'fantasticauth_org_data';
const BIOMETRIC_ENABLED_KEY = 'fantasticauth_biometric_enabled';
const LEGACY_TOKEN_KEY = 'vault_session_token';
const LEGACY_REFRESH_TOKEN_KEY = 'vault_refresh_token';
const LEGACY_USER_DATA_KEY = 'vault_user_data';
const LEGACY_ORG_DATA_KEY = 'vault_org_data';
const LEGACY_BIOMETRIC_ENABLED_KEY = 'vault_biometric_enabled';

// ============================================================================
// Platform Detection
// ============================================================================

let Keychain: any = null;
let AsyncStorage: any = null;
let SecureStore: any = null;

// Try to load optional dependencies
try {
  Keychain = require('react-native-keychain');
} catch {
  // Keychain not available
}

try {
  AsyncStorage = require('@react-native-async-storage/async-storage').default;
} catch {
  // AsyncStorage not available
}

try {
  SecureStore = require('expo-secure-store');
} catch {
  // Expo SecureStore not available
}

// ============================================================================
// Secure Storage Implementation
// ============================================================================

/**
 * Check if secure storage is available
 */
export function isSecureStorageAvailable(): boolean {
  return !!(Keychain || SecureStore);
}

/**
 * Check if running in Expo environment
 */
function isExpo(): boolean {
  return !!SecureStore;
}

/**
 * Set an item in secure storage
 */
export async function setItem(
  key: string, 
  value: string, 
  options: SecureStorageOptions = {}
): Promise<void> {
  const { service = VAULT_SERVICE, accessibility = 'WhenUnlocked', storageType } = options;

  if (isExpo()) {
    // Use Expo SecureStore
    await SecureStore.setItemAsync(key, value, {
      keychainService: service,
    });
    return;
  }

  if (Keychain) {
    // Use react-native-keychain
    const keychainOptions: any = {
      service,
      accessible: accessibility,
    };

    if (Platform.OS === 'android' && storageType) {
      keychainOptions.storage = storageType;
    }

    await Keychain.setGenericPassword(key, value, keychainOptions);
    return;
  }

  // Fallback to AsyncStorage (not recommended for sensitive data)
  if (AsyncStorage) {
    await AsyncStorage.setItem(key, value);
    return;
  }

  throw new Error('No storage implementation available');
}

/**
 * Get an item from secure storage
 */
export async function getItem(
  key: string, 
  options: SecureStorageOptions = {}
): Promise<string | null> {
  const { service = VAULT_SERVICE, storageType } = options;

  if (isExpo()) {
    // Use Expo SecureStore
    return SecureStore.getItemAsync(key, {
      keychainService: service,
    });
  }

  if (Keychain) {
    // Use react-native-keychain
    const keychainOptions: any = {
      service,
    };

    if (Platform.OS === 'android' && storageType) {
      keychainOptions.storage = storageType;
    }

    try {
      const credentials = await Keychain.getGenericPassword(keychainOptions);
      if (credentials && credentials.username === key) {
        return credentials.password;
      }
      return null;
    } catch {
      return null;
    }
  }

  // Fallback to AsyncStorage
  if (AsyncStorage) {
    return AsyncStorage.getItem(key);
  }

  return null;
}

/**
 * Remove an item from secure storage
 */
export async function removeItem(
  key: string, 
  options: SecureStorageOptions = {}
): Promise<void> {
  const { service = VAULT_SERVICE, storageType } = options;

  if (isExpo()) {
    // Use Expo SecureStore
    await SecureStore.deleteItemAsync(key, {
      keychainService: service,
    });
    return;
  }

  if (Keychain) {
    // Use react-native-keychain
    const keychainOptions: any = {
      service,
    };

    if (Platform.OS === 'android' && storageType) {
      keychainOptions.storage = storageType;
    }

    await Keychain.resetGenericPassword(keychainOptions);
    return;
  }

  // Fallback to AsyncStorage
  if (AsyncStorage) {
    await AsyncStorage.removeItem(key);
    return;
  }
}

/**
 * Check if an item exists in secure storage
 */
export async function hasItem(
  key: string, 
  options: SecureStorageOptions = {}
): Promise<boolean> {
  const value = await getItem(key, options);
  return value !== null;
}

/**
 * Clear all vault-related items from secure storage
 */
export async function clearVaultStorage(options: SecureStorageOptions = {}): Promise<void> {
  const keys = [
    TOKEN_KEY,
    REFRESH_TOKEN_KEY,
    USER_DATA_KEY,
    ORG_DATA_KEY,
    BIOMETRIC_ENABLED_KEY,
    LEGACY_TOKEN_KEY,
    LEGACY_REFRESH_TOKEN_KEY,
    LEGACY_USER_DATA_KEY,
    LEGACY_ORG_DATA_KEY,
    LEGACY_BIOMETRIC_ENABLED_KEY,
  ];

  await Promise.all(keys.map(key => removeItem(key, options)));
}

// ============================================================================
// Session Token Management
// ============================================================================

/**
 * Store session token
 */
export async function storeSessionToken(token: string): Promise<void> {
  await setItem(TOKEN_KEY, token, {
    accessibility: 'AfterFirstUnlockThisDeviceOnly',
  });
  await removeItem(LEGACY_TOKEN_KEY);
}

/**
 * Get stored session token
 */
export async function getSessionToken(): Promise<string | null> {
  const token = await getItem(TOKEN_KEY);
  return token || getItem(LEGACY_TOKEN_KEY);
}

/**
 * Store refresh token
 */
export async function storeRefreshToken(token: string): Promise<void> {
  await setItem(REFRESH_TOKEN_KEY, token, {
    accessibility: 'AfterFirstUnlockThisDeviceOnly',
  });
  await removeItem(LEGACY_REFRESH_TOKEN_KEY);
}

/**
 * Get stored refresh token
 */
export async function getRefreshToken(): Promise<string | null> {
  const token = await getItem(REFRESH_TOKEN_KEY);
  return token || getItem(LEGACY_REFRESH_TOKEN_KEY);
}

/**
 * Clear session tokens
 */
export async function clearSessionTokens(): Promise<void> {
  await Promise.all([
    removeItem(TOKEN_KEY),
    removeItem(REFRESH_TOKEN_KEY),
    removeItem(LEGACY_TOKEN_KEY),
    removeItem(LEGACY_REFRESH_TOKEN_KEY),
  ]);
}

// ============================================================================
// User Data Caching
// ============================================================================

/**
 * Store cached user data
 */
export async function storeCachedUser(user: any): Promise<void> {
  await setItem(USER_DATA_KEY, JSON.stringify(user));
  await removeItem(LEGACY_USER_DATA_KEY);
}

/**
 * Get cached user data
 */
export async function getCachedUser(): Promise<any | null> {
  const data = (await getItem(USER_DATA_KEY)) || (await getItem(LEGACY_USER_DATA_KEY));
  if (data) {
    try {
      return JSON.parse(data);
    } catch {
      return null;
    }
  }
  return null;
}

/**
 * Store cached organization data
 */
export async function storeCachedOrganizations(orgs: any[]): Promise<void> {
  await setItem(ORG_DATA_KEY, JSON.stringify(orgs));
  await removeItem(LEGACY_ORG_DATA_KEY);
}

/**
 * Get cached organization data
 */
export async function getCachedOrganizations(): Promise<any[] | null> {
  const data = (await getItem(ORG_DATA_KEY)) || (await getItem(LEGACY_ORG_DATA_KEY));
  if (data) {
    try {
      return JSON.parse(data);
    } catch {
      return null;
    }
  }
  return null;
}

// ============================================================================
// Biometric Settings
// ============================================================================

/**
 * Check if biometric unlock is enabled
 */
export async function isBiometricEnabled(): Promise<boolean> {
  const value =
    (await getItem(BIOMETRIC_ENABLED_KEY)) ||
    (await getItem(LEGACY_BIOMETRIC_ENABLED_KEY));
  return value === 'true';
}

/**
 * Enable/disable biometric unlock
 */
export async function setBiometricEnabled(enabled: boolean): Promise<void> {
  await setItem(BIOMETRIC_ENABLED_KEY, enabled ? 'true' : 'false');
  await removeItem(LEGACY_BIOMETRIC_ENABLED_KEY);
}

// ============================================================================
// Generic Storage (for non-sensitive data)
// ============================================================================

/**
 * Set a generic item (uses AsyncStorage)
 */
export async function setGenericItem(key: string, value: string): Promise<void> {
  if (!AsyncStorage) {
    throw new Error('AsyncStorage not available');
  }
  await AsyncStorage.setItem(key, value);
}

/**
 * Get a generic item (uses AsyncStorage)
 */
export async function getGenericItem(key: string): Promise<string | null> {
  if (!AsyncStorage) {
    return null;
  }
  return AsyncStorage.getItem(key);
}

/**
 * Remove a generic item (uses AsyncStorage)
 */
export async function removeGenericItem(key: string): Promise<void> {
  if (!AsyncStorage) {
    return;
  }
  await AsyncStorage.removeItem(key);
}

// ============================================================================
// Export SecureStorage object for convenience
// ============================================================================

export const SecureStorage = {
  setItem,
  getItem,
  removeItem,
  hasItem,
  clearVaultStorage,
  storeSessionToken,
  getSessionToken,
  storeRefreshToken,
  getRefreshToken,
  clearSessionTokens,
  storeCachedUser,
  getCachedUser,
  storeCachedOrganizations,
  getCachedOrganizations,
  isBiometricEnabled,
  setBiometricEnabled,
  setGenericItem,
  getGenericItem,
  removeGenericItem,
  isAvailable: isSecureStorageAvailable,
};

export default SecureStorage;
