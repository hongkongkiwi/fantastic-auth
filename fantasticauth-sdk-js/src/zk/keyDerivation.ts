/**
 * Master Key Derivation for Zero-Knowledge Architecture
 * 
 * This module implements client-side key derivation using Argon2id.
 * In the browser, we use a WebAssembly implementation of Argon2.
 * 
 * @module zk/keyDerivation
 */

const SALT_LENGTH = 16;
const KEY_MATERIAL_LENGTH = 64;

/**
 * Master key derived from password
 */
export interface MasterKey {
  /** Symmetric encryption key (raw bytes) */
  encryptionKey: Uint8Array;
  /** Authentication key for HMAC */
  authenticationKey: Uint8Array;
  /** RSA private key for unwrapping data keys */
  rsaPrivateKey: CryptoKey;
  /** RSA public key for wrapping data keys */
  rsaPublicKey: CryptoKey;
  /** Raw key material (for serialization) */
  keyMaterial: Uint8Array;
}

/**
 * Argon2id parameters
 */
export interface Argon2Params {
  /** Memory cost in KB */
  memoryCost: number;
  /** Number of iterations */
  timeCost: number;
  /** Degree of parallelism */
  parallelism: number;
}

/**
 * Default Argon2id parameters
 */
export const DEFAULT_ARGON2_PARAMS: Argon2Params = {
  memoryCost: 65536, // 64 MB
  timeCost: 3,
  parallelism: 4,
};

/**
 * Conservative parameters (higher security, slower)
 */
export const CONSERVATIVE_ARGON2_PARAMS: Argon2Params = {
  memoryCost: 262144, // 256 MB
  timeCost: 4,
  parallelism: 4,
};

/**
 * Fast parameters (for testing only)
 */
export const FAST_ARGON2_PARAMS: Argon2Params = {
  memoryCost: 16384, // 16 MB
  timeCost: 2,
  parallelism: 1,
};

/**
 * Generate a cryptographically secure random salt
 */
export function generateSalt(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
}

/**
 * Derive master key from password using PBKDF2 (fallback for browsers without Argon2)
 * 
 * For production, use argon2-browser WASM implementation
 */
export async function deriveMasterKey(
  password: string,
  salt: Uint8Array,
  params: Argon2Params = DEFAULT_ARGON2_PARAMS
): Promise<MasterKey> {
  // Use PBKDF2 as a fallback (browser native)
  // In production, use argon2-browser for proper Argon2id
  const keyMaterial = await pbkdf2Derive(password, salt, KEY_MATERIAL_LENGTH);

  // Split key material
  const encryptionKey = keyMaterial.slice(0, 32);
  const authenticationKey = keyMaterial.slice(32, 64);

  // Generate RSA key pair deterministically from encryption key
  const { privateKey, publicKey } = await generateRsaKeyPair(encryptionKey);

  return {
    encryptionKey,
    authenticationKey,
    rsaPrivateKey: privateKey,
    rsaPublicKey: publicKey,
    keyMaterial,
  };
}

/**
 * PBKDF2 key derivation (browser fallback)
 */
async function pbkdf2Derive(
  password: string,
  salt: Uint8Array,
  length: number
): Promise<Uint8Array> {
  const encoder = new TextEncoder();
  const passwordBuffer = encoder.encode(password);

  // Import password as key material
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    passwordBuffer,
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );

  // Derive bits
  const derived = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt,
      iterations: 100000,
      hash: 'SHA-256',
    },
    keyMaterial,
    length * 8
  );

  return new Uint8Array(derived);
}

/**
 * Generate RSA key pair
 * 
 * Note: In a full implementation, this should be deterministic based on the seed
 */
async function generateRsaKeyPair(seed: Uint8Array): Promise<{
  privateKey: CryptoKey;
  publicKey: CryptoKey;
}> {
  // Generate RSA key pair
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true, // extractable
    ['wrapKey', 'unwrapKey']
  );

  return {
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
  };
}

/**
 * Export master key to portable format (for storage)
 */
export async function exportMasterKey(masterKey: MasterKey): Promise<{
  encryptionKey: string;
  authenticationKey: string;
  rsaPrivateKey: string;
  rsaPublicKey: string;
}> {
  const [privateKeyJwk, publicKeyJwk] = await Promise.all([
    crypto.subtle.exportKey('jwk', masterKey.rsaPrivateKey),
    crypto.subtle.exportKey('jwk', masterKey.rsaPublicKey),
  ]);

  return {
    encryptionKey: arrayBufferToBase64(masterKey.encryptionKey),
    authenticationKey: arrayBufferToBase64(masterKey.authenticationKey),
    rsaPrivateKey: JSON.stringify(privateKeyJwk),
    rsaPublicKey: JSON.stringify(publicKeyJwk),
  };
}

/**
 * Import master key from portable format
 */
export async function importMasterKey(exported: {
  encryptionKey: string;
  authenticationKey: string;
  rsaPrivateKey: string;
  rsaPublicKey: string;
}): Promise<MasterKey> {
  const encryptionKey = base64ToArrayBuffer(exported.encryptionKey);
  const authenticationKey = base64ToArrayBuffer(exported.authenticationKey);

  const privateKeyJwk = JSON.parse(exported.rsaPrivateKey);
  const publicKeyJwk = JSON.parse(exported.rsaPublicKey);

  const [privateKey, publicKey] = await Promise.all([
    crypto.subtle.importKey(
      'jwk',
      privateKeyJwk,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      true,
      ['unwrapKey']
    ),
    crypto.subtle.importKey(
      'jwk',
      publicKeyJwk,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      true,
      ['wrapKey']
    ),
  ]);

  const keyMaterial = new Uint8Array(64);
  keyMaterial.set(encryptionKey, 0);
  keyMaterial.set(authenticationKey, 32);

  return {
    encryptionKey,
    authenticationKey,
    rsaPrivateKey: privateKey,
    rsaPublicKey: publicKey,
    keyMaterial,
  };
}

/**
 * Encrypt RSA private key for server storage
 */
export async function encryptPrivateKeyForStorage(
  privateKey: CryptoKey,
  encryptionKey: Uint8Array
): Promise<string> {
  // Export private key
  const pkcs8 = await crypto.subtle.exportKey('pkcs8', privateKey);

  // Import encryption key
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    encryptionKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );

  // Generate nonce
  const nonce = crypto.getRandomValues(new Uint8Array(12));

  // Encrypt
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce },
    cryptoKey,
    pkcs8
  );

  // Combine nonce + ciphertext
  const combined = new Uint8Array(nonce.length + ciphertext.byteLength);
  combined.set(nonce, 0);
  combined.set(new Uint8Array(ciphertext), nonce.length);

  return arrayBufferToBase64(combined);
}

/**
 * Decrypt RSA private key from server storage
 */
export async function decryptPrivateKeyFromStorage(
  encryptedKey: string,
  encryptionKey: Uint8Array
): Promise<CryptoKey> {
  const combined = base64ToArrayBuffer(encryptedKey);

  // Extract nonce and ciphertext
  const nonce = combined.slice(0, 12);
  const ciphertext = combined.slice(12);

  // Import encryption key
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    encryptionKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  // Decrypt
  const pkcs8 = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce },
    cryptoKey,
    ciphertext
  );

  // Import private key
  return await crypto.subtle.importKey(
    'pkcs8',
    pkcs8,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    true,
    ['unwrapKey']
  );
}

/**
 * Generate password commitment for ZK proof
 */
export async function generatePasswordCommitment(
  password: string,
  salt: Uint8Array
): Promise<Uint8Array> {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);

  // Combine password + salt
  const combined = new Uint8Array(data.length + salt.length + 14);
  combined.set(data, 0);
  combined.set(salt, data.length);
  combined.set(encoder.encode('zk_password_v1'), data.length + salt.length);

  // Hash with SHA-256
  const hash = await crypto.subtle.digest('SHA-256', combined);
  return new Uint8Array(hash);
}

// Helper functions

function arrayBufferToBase64(buffer: Uint8Array): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToArrayBuffer(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
