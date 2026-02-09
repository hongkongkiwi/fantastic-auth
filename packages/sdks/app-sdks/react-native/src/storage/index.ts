/**
 * Secure Storage Module
 * 
 * Secure storage for React Native using iOS Keychain and Android Keystore.
 * 
 * @example
 * ```typescript
 * import { SecureStorage } from '@fantasticauth/react-native';
 * 
 * // Store session token securely
 * await SecureStorage.setItem('fantasticauth_session_token', token);
 * 
 * // Retrieve session token
 * const token = await SecureStorage.getItem('fantasticauth_session_token');
 * 
 * // Remove item
 * await SecureStorage.removeItem('fantasticauth_session_token');
 * ```
 */

export {
  // Main storage functions
  setItem,
  getItem,
  removeItem,
  hasItem,
  clearVaultStorage,
  isSecureStorageAvailable,
  SecureStorage,
} from './secure-storage';

export {
  // Session token management
  storeSessionToken,
  getSessionToken,
  storeRefreshToken,
  getRefreshToken,
  clearSessionTokens,
} from './secure-storage';

export {
  // User data caching
  storeCachedUser,
  getCachedUser,
  storeCachedOrganizations,
  getCachedOrganizations,
} from './secure-storage';

export {
  // Biometric settings
  isBiometricEnabled,
  setBiometricEnabled,
} from './secure-storage';

export {
  // Generic storage
  setGenericItem,
  getGenericItem,
  removeGenericItem,
} from './secure-storage';

export type {
  SecureStorageOptions,
  SecureStorageItem,
} from '../types';
