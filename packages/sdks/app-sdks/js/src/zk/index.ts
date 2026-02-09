/**
 * Zero-Knowledge Architecture SDK
 * 
 * This module provides client-side encryption for the Vault SDK.
 * All encryption happens in the browser - the server never sees plaintext data.
 * 
 * @example
 * ```typescript
 * import { 
 *   deriveMasterKey, 
 *   encryptUserData, 
 *   decryptUserData,
 *   ZkPasswordProver 
 * } from '@fantasticauth/sdk/zk';
 * 
 * // Derive master key from password
 * const salt = generateSalt();
 * const masterKey = await deriveMasterKey(password, salt);
 * 
 * // Encrypt user data
 * const encrypted = await encryptUserData(userProfile, masterKey);
 * 
 * // Send to server (server never sees plaintext)
 * await api.storeEncryptedData(encrypted);
 * 
 * // Later: decrypt
 * const decrypted = await decryptUserData(encrypted, masterKey);
 * ```
 * 
 * @module zk
 */

// Key derivation
export {
  deriveMasterKey,
  exportMasterKey,
  importMasterKey,
  generateSalt,
  encryptPrivateKeyForStorage,
  decryptPrivateKeyFromStorage,
  generatePasswordCommitment,
  DEFAULT_ARGON2_PARAMS,
  CONSERVATIVE_ARGON2_PARAMS,
  FAST_ARGON2_PARAMS,
} from './keyDerivation';
export type { MasterKey, Argon2Params } from './keyDerivation';

// Encryption
export {
  generateDek,
  wrapDek,
  unwrapDek,
  aesGcmEncrypt,
  aesGcmDecrypt,
  encryptUserData,
  decryptUserData,
  encryptWithMasterKey,
  decryptWithMasterKey,
  serializeEncryptedData,
  deserializeEncryptedData,
} from './encryption';
export type {
  DataEncryptionKey,
  WrappedDek,
  EncryptedUserData,
  UserProfile,
  Address,
} from './encryption';

// Proofs
export {
  ZkPasswordProver,
  ZkPasswordVerifier,
  ZkAuthentication,
  generateChallenge,
  serializeProof,
  deserializeProof,
} from './proofs';
export type { ZkPasswordProof } from './proofs';

// Recovery
export {
  SocialRecovery,
  ShareValidator,
  RecoverySessionManager,
  RecoverySessionStatus,
} from './recovery';
export type {
  RecoveryShare,
  ShareMetadata,
  RecoverySession,
} from './recovery';

/**
 * Zero-knowledge module version
 */
export const ZK_VERSION = '1.0.0';

/**
 * Check if Web Crypto API is available
 */
export function isWebCryptoAvailable(): boolean {
  return typeof crypto !== 'undefined' && 
         typeof crypto.subtle !== 'undefined';
}

/**
 * Initialize the zero-knowledge module
 * 
 * @throws Error if Web Crypto API is not available
 */
export function initZk(): void {
  if (!isWebCryptoAvailable()) {
    throw new Error(
      'Web Crypto API is not available. ' +
      'Please use a modern browser with HTTPS.'
    );
  }
}

/**
 * Zero-knowledge error types
 */
export class ZkError extends Error {
  constructor(
    message: string,
    public code: string,
    public details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'ZkError';
  }
}

/**
 * Encryption error
 */
export class ZkEncryptionError extends ZkError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, 'ZK_ENCRYPTION_ERROR', details);
    this.name = 'ZkEncryptionError';
  }
}

/**
 * Key derivation error
 */
export class ZkKeyDerivationError extends ZkError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, 'ZK_KEY_DERIVATION_ERROR', details);
    this.name = 'ZkKeyDerivationError';
  }
}

/**
 * Proof error
 */
export class ZkProofError extends ZkError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, 'ZK_PROOF_ERROR', details);
    this.name = 'ZkProofError';
  }
}

/**
 * Recovery error
 */
export class ZkRecoveryError extends ZkError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, 'ZK_RECOVERY_ERROR', details);
    this.name = 'ZkRecoveryError';
  }
}
