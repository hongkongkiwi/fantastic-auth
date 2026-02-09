/**
 * Client-Side Encryption for Zero-Knowledge Architecture
 * 
 * This module implements browser-based encryption ensuring that user data
 * is encrypted before being sent to the server. The server only stores
 * encrypted blobs and cannot decrypt them.
 * 
 * @module zk/encryption
 */

import { deriveMasterKey, MasterKey } from './keyDerivation';

const AES_GCM_ALGORITHM = 'AES-GCM';
const RSA_OAEP_ALGORITHM = 'RSA-OAEP';
const AES_KEY_SIZE = 256;
const AES_IV_SIZE = 12;
const RSA_KEY_SIZE = 2048;

/**
 * Data Encryption Key - 256 bits random key
 */
export type DataEncryptionKey = CryptoKey;

/**
 * Wrapped (encrypted) DEK
 */
export interface WrappedDek {
  /** RSA-OAEP encrypted DEK */
  ciphertext: Uint8Array;
}

/**
 * Encrypted user data with all necessary metadata
 */
export interface EncryptedUserData {
  /** Protocol version */
  version: number;
  /** AES-GCM ciphertext */
  ciphertext: Uint8Array;
  /** IV/nonce (12 bytes) */
  nonce: Uint8Array;
  /** RSA-OAEP wrapped data encryption key */
  encryptedDek: WrappedDek;
  /** Timestamp of encryption */
  encryptedAt: string;
}

/**
 * User profile data structure
 */
export interface UserProfile {
  name?: string;
  givenName?: string;
  familyName?: string;
  middleName?: string;
  nickname?: string;
  preferredUsername?: string;
  profile?: string;
  picture?: string;
  website?: string;
  gender?: string;
  birthdate?: string;
  zoneinfo?: string;
  locale?: string;
  email?: string;
  phoneNumber?: string;
  phoneNumberVerified?: boolean;
  address?: Address;
  [key: string]: unknown;
}

/**
 * Physical address
 */
export interface Address {
  formatted?: string;
  streetAddress?: string;
  locality?: string;
  region?: string;
  postalCode?: string;
  country?: string;
}

/**
 * Generate a random Data Encryption Key
 */
export async function generateDek(): Promise<DataEncryptionKey> {
  return await crypto.subtle.generateKey(
    {
      name: AES_GCM_ALGORITHM,
      length: AES_KEY_SIZE,
    },
    true, // extractable
    ['encrypt', 'decrypt']
  );
}

/**
 * Wrap DEK with RSA public key using RSA-OAEP
 */
export async function wrapDek(
  dek: DataEncryptionKey,
  publicKey: CryptoKey
): Promise<WrappedDek> {
  // Export DEK to raw format
  const dekRaw = await crypto.subtle.exportKey('raw', dek);

  // Wrap with RSA-OAEP
  const wrapped = await crypto.subtle.wrapKey(
    'raw',
    dek,
    publicKey,
    {
      name: RSA_OAEP_ALGORITHM,
      hash: 'SHA-256',
    }
  );

  return {
    ciphertext: new Uint8Array(wrapped),
  };
}

/**
 * Unwrap DEK with RSA private key
 */
export async function unwrapDek(
  wrappedDek: WrappedDek,
  privateKey: CryptoKey
): Promise<DataEncryptionKey> {
  return await crypto.subtle.unwrapKey(
    'raw',
    wrappedDek.ciphertext,
    privateKey,
    {
      name: RSA_OAEP_ALGORITHM,
      hash: 'SHA-256',
    },
    {
      name: AES_GCM_ALGORITHM,
      length: AES_KEY_SIZE,
    },
    true,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypt data with AES-GCM
 */
export async function aesGcmEncrypt(
  data: Uint8Array,
  key: CryptoKey
): Promise<{ ciphertext: Uint8Array; nonce: Uint8Array }> {
  // Generate random nonce
  const nonce = crypto.getRandomValues(new Uint8Array(AES_IV_SIZE));

  // Encrypt
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: AES_GCM_ALGORITHM,
      iv: nonce,
    },
    key,
    data
  );

  return {
    ciphertext: new Uint8Array(ciphertext),
    nonce,
  };
}

/**
 * Decrypt data with AES-GCM
 */
export async function aesGcmDecrypt(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  key: CryptoKey
): Promise<Uint8Array> {
  const plaintext = await crypto.subtle.decrypt(
    {
      name: AES_GCM_ALGORITHM,
      iv: nonce,
    },
    key,
    ciphertext
  );

  return new Uint8Array(plaintext);
}

/**
 * Encrypt user profile data
 */
export async function encryptUserData(
  profile: UserProfile,
  masterKey: MasterKey
): Promise<EncryptedUserData> {
  // Serialize profile to JSON
  const plaintext = new TextEncoder().encode(JSON.stringify(profile));

  // Generate random DEK
  const dek = await generateDek();

  // Encrypt data with DEK
  const { ciphertext, nonce } = await aesGcmEncrypt(plaintext, dek);

  // Wrap DEK with RSA public key
  const encryptedDek = await wrapDek(dek, masterKey.rsaPublicKey);

  return {
    version: 1,
    ciphertext,
    nonce,
    encryptedDek,
    encryptedAt: new Date().toISOString(),
  };
}

/**
 * Decrypt user profile data
 */
export async function decryptUserData(
  encryptedData: EncryptedUserData,
  masterKey: MasterKey
): Promise<UserProfile> {
  // Unwrap DEK
  const dek = await unwrapDek(encryptedData.encryptedDek, masterKey.rsaPrivateKey);

  // Decrypt data
  const plaintext = await aesGcmDecrypt(
    encryptedData.ciphertext,
    encryptedData.nonce,
    dek
  );

  // Parse JSON
  const json = new TextDecoder().decode(plaintext);
  return JSON.parse(json) as UserProfile;
}

/**
 * Serialize encrypted data for transmission
 */
export function serializeEncryptedData(data: EncryptedUserData): string {
  const obj = {
    version: data.version,
    ciphertext: arrayBufferToBase64(data.ciphertext),
    nonce: arrayBufferToBase64(data.nonce),
    encryptedDek: {
      ciphertext: arrayBufferToBase64(data.encryptedDek.ciphertext),
    },
    encryptedAt: data.encryptedAt,
  };
  return JSON.stringify(obj);
}

/**
 * Deserialize encrypted data from transmission
 */
export function deserializeEncryptedData(json: string): EncryptedUserData {
  const obj = JSON.parse(json);
  return {
    version: obj.version,
    ciphertext: base64ToArrayBuffer(obj.ciphertext),
    nonce: base64ToArrayBuffer(obj.nonce),
    encryptedDek: {
      ciphertext: base64ToArrayBuffer(obj.encryptedDek.ciphertext),
    },
    encryptedAt: obj.encryptedAt,
  };
}

/**
 * Encrypt arbitrary data with master key
 */
export async function encryptWithMasterKey(
  data: Uint8Array,
  masterKey: MasterKey
): Promise<EncryptedUserData> {
  const dek = await generateDek();
  const { ciphertext, nonce } = await aesGcmEncrypt(data, dek);
  const encryptedDek = await wrapDek(dek, masterKey.rsaPublicKey);

  return {
    version: 1,
    ciphertext,
    nonce,
    encryptedDek,
    encryptedAt: new Date().toISOString(),
  };
}

/**
 * Decrypt arbitrary data with master key
 */
export async function decryptWithMasterKey(
  encryptedData: EncryptedUserData,
  masterKey: MasterKey
): Promise<Uint8Array> {
  const dek = await unwrapDek(encryptedData.encryptedDek, masterKey.rsaPrivateKey);
  return await aesGcmDecrypt(
    encryptedData.ciphertext,
    encryptedData.nonce,
    dek
  );
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
