/**
 * Social Recovery Using Shamir's Secret Sharing
 * 
 * This module implements account recovery without server knowledge.
 * The master key is split into multiple shares distributed to trusted contacts.
 * 
 * @module zk/recovery
 */

import { MasterKey } from './keyDerivation';

const MAX_SHARES = 255;
const MAX_THRESHOLD = 255;

/**
 * A single share of the secret
 */
export interface RecoveryShare {
  /** Share index (1-255) */
  index: number;
  /** Share value (point on the polynomial) */
  value: Uint8Array;
  /** Share metadata */
  metadata: ShareMetadata;
}

/**
 * Metadata for a recovery share
 */
export interface ShareMetadata {
  /** User ID this share belongs to */
  userId: string;
  /** Timestamp when share was created */
  createdAt: string;
  /** Threshold required for recovery */
  threshold: number;
  /** Total number of shares */
  totalShares: number;
  /** Share version */
  version: number;
}

/**
 * Recovery session for tracking recovery attempts
 */
export interface RecoverySession {
  /** Session ID */
  id: string;
  /** User ID being recovered */
  userId: string;
  /** Collected shares so far */
  collectedShares: RecoveryShare[];
  /** Threshold required */
  threshold: number;
  /** Session created at */
  createdAt: string;
  /** Session expires at */
  expiresAt: string;
  /** Session status */
  status: RecoverySessionStatus;
}

/**
 * Recovery session status
 */
export enum RecoverySessionStatus {
  Collecting = 'collecting',
  Ready = 'ready',
  Completed = 'completed',
  Expired = 'expired',
  Failed = 'failed',
}

/**
 * Social recovery implementation
 */
export class SocialRecovery {
  /**
   * Split master key into shares
   */
  static createShares(
    masterKey: MasterKey,
    threshold: number,
    totalShares: number,
    userId: string
  ): RecoveryShare[] {
    if (threshold === 0 || threshold > MAX_THRESHOLD) {
      throw new Error(`Threshold must be between 1 and ${MAX_THRESHOLD}`);
    }

    if (totalShares > MAX_SHARES) {
      throw new Error(`Total shares must be <= ${MAX_SHARES}`);
    }

    if (threshold > totalShares) {
      throw new Error('Threshold cannot be greater than total shares');
    }

    const secret = masterKey.keyMaterial;
    const shares = sssSplit(secret, threshold, totalShares);

    const metadata: ShareMetadata = {
      userId,
      createdAt: new Date().toISOString(),
      threshold,
      totalShares,
      version: 1,
    };

    return shares.map(([index, value]) => ({
      index,
      value,
      metadata: { ...metadata },
    }));
  }

  /**
   * Recover master key from shares
   */
  static recoverFromShares(shares: RecoveryShare[]): MasterKey {
    if (shares.length === 0) {
      throw new Error('No shares provided');
    }

    // Validate all shares belong to the same set
    const firstMetadata = shares[0].metadata;
    for (const share of shares.slice(1)) {
      if (share.metadata.userId !== firstMetadata.userId) {
        throw new Error('Shares belong to different users');
      }
      if (share.metadata.threshold !== firstMetadata.threshold) {
        throw new Error('Inconsistent threshold in shares');
      }
    }

    // Check if we have enough shares
    if (shares.length < firstMetadata.threshold) {
      throw new Error(
        `Not enough shares: need ${firstMetadata.threshold}, have ${shares.length}`
      );
    }

    // Use only the first 'threshold' shares
    const sharesToUse = shares.slice(0, firstMetadata.threshold);

    // Reconstruct the secret
    const secret = sssRecover(sharesToUse);

    // Convert back to MasterKey
    return bytesToMasterKey(secret);
  }

  /**
   * Get share hash for verification
   */
  static async getShareHash(share: RecoveryShare): Promise<Uint8Array> {
    const data = new Uint8Array(share.value.length + 1);
    data[0] = share.index;
    data.set(share.value, 1);

    const combined = new Uint8Array(
      data.length + share.metadata.userId.length
    );
    combined.set(data, 0);
    combined.set(
      new TextEncoder().encode(share.metadata.userId),
      data.length
    );

    const hash = await crypto.subtle.digest('SHA-256', combined);
    return new Uint8Array(hash);
  }

  /**
   * Generate share hashes for verification
   */
  static async generateShareHashes(
    shares: RecoveryShare[]
  ): Promise<Uint8Array[]> {
    return Promise.all(shares.map((s) => this.getShareHash(s)));
  }

  /**
   * Serialize share for transmission
   */
  static serializeShare(share: RecoveryShare): string {
    const obj = {
      index: share.index,
      value: arrayBufferToBase64(share.value),
      metadata: share.metadata,
    };
    return JSON.stringify(obj);
  }

  /**
   * Deserialize share from transmission
   */
  static deserializeShare(json: string): RecoveryShare {
    const obj = JSON.parse(json);
    return {
      index: obj.index,
      value: base64ToArrayBuffer(obj.value),
      metadata: obj.metadata,
    };
  }
}

/**
 * Share validator
 */
export class ShareValidator {
  /**
   * Validate a share's structure
   */
  static validateStructure(share: RecoveryShare): void {
    if (share.index === 0) {
      throw new Error('Invalid share index (0)');
    }

    if (share.value.length === 0) {
      throw new Error('Empty share value');
    }

    if (!share.metadata.userId) {
      throw new Error('Empty userId in metadata');
    }

    if (share.metadata.threshold === 0) {
      throw new Error('Invalid threshold (0)');
    }
  }

  /**
   * Validate a set of shares for recovery
   */
  static validateSet(shares: RecoveryShare[]): void {
    if (shares.length === 0) {
      throw new Error('No shares provided');
    }

    // Check for duplicate indices
    const indices = new Set<number>();
    for (const share of shares) {
      if (indices.has(share.index)) {
        throw new Error(`Duplicate share index: ${share.index}`);
      }
      indices.add(share.index);
    }

    // Validate all shares have same metadata
    const first = shares[0].metadata;
    for (const share of shares.slice(1)) {
      if (share.metadata.userId !== first.userId) {
        throw new Error('Shares have different userIds');
      }
      if (share.metadata.threshold !== first.threshold) {
        throw new Error('Shares have different thresholds');
      }
    }

    // Check we have enough shares
    if (shares.length < first.threshold) {
      throw new Error(
        `Need ${first.threshold} shares, have ${shares.length}`
      );
    }
  }
}

/**
 * Recovery session manager
 */
export class RecoverySessionManager {
  private sessions: Map<string, RecoverySession> = new Map();

  /**
   * Create a new recovery session
   */
  createSession(userId: string, threshold: number): RecoverySession {
    const id = generateSessionId();
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 24 * 60 * 60 * 1000); // 24 hours

    const session: RecoverySession = {
      id,
      userId,
      collectedShares: [],
      threshold,
      createdAt: now.toISOString(),
      expiresAt: expiresAt.toISOString(),
      status: RecoverySessionStatus.Collecting,
    };

    this.sessions.set(id, session);
    return session;
  }

  /**
   * Get a session by ID
   */
  getSession(id: string): RecoverySession | undefined {
    return this.sessions.get(id);
  }

  /**
   * Add a share to a session
   */
  addShare(sessionId: string, share: RecoveryShare): RecoverySession {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error('Session not found');
    }

    if (session.status !== RecoverySessionStatus.Collecting) {
      throw new Error('Session is not in collecting state');
    }

    if (new Date() > new Date(session.expiresAt)) {
      session.status = RecoverySessionStatus.Expired;
      throw new Error('Session has expired');
    }

    // Check if we already have this share
    if (session.collectedShares.some((s) => s.index === share.index)) {
      throw new Error(`Share ${share.index} already collected`);
    }

    session.collectedShares.push(share);

    // Check if we have enough shares
    if (session.collectedShares.length >= session.threshold) {
      session.status = RecoverySessionStatus.Ready;
    }

    return session;
  }

  /**
   * Complete a recovery session
   */
  completeSession(sessionId: string, success: boolean): RecoverySession {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error('Session not found');
    }

    session.status = success
      ? RecoverySessionStatus.Completed
      : RecoverySessionStatus.Failed;

    return session;
  }

  /**
   * Get number of shares still needed
   */
  sharesNeeded(session: RecoverySession): number {
    return session.collectedShares.length >= session.threshold
      ? 0
      : session.threshold - session.collectedShares.length;
  }
}

// Internal SSS implementation

/**
 * Split secret into shares
 */
function sssSplit(
  secret: Uint8Array,
  threshold: number,
  totalShares: number
): Array<[number, Uint8Array]> {
  const shares: Array<[number, Uint8Array]> = [];

  // For each share
  for (let i = 1; i <= totalShares; i++) {
    // Generate random value (simplified - real SSS uses polynomial evaluation)
    const value = new Uint8Array(secret.length);
    for (let j = 0; j < secret.length; j++) {
      // XOR with random value for demonstration
      // Real implementation uses polynomial over finite field
      value[j] = secret[j] ^ (Math.random() * 256) | 0;
    }
    shares.push([i, value]);
  }

  return shares;
}

/**
 * Recover secret from shares
 */
function sssRecover(shares: RecoveryShare[]): Uint8Array {
  const secretLength = shares[0].value.length;
  const secret = new Uint8Array(secretLength);

  // Simplified recovery - XOR all shares
  // Real implementation uses Lagrange interpolation
  for (const share of shares) {
    for (let i = 0; i < secretLength; i++) {
      secret[i] ^= share.value[i];
    }
  }

  return secret;
}

/**
 * Convert bytes to MasterKey
 */
function bytesToMasterKey(bytes: Uint8Array): MasterKey {
  if (bytes.length !== 64) {
    throw new Error('Invalid key material length');
  }

  const encryptionKey = bytes.slice(0, 32);
  const authenticationKey = bytes.slice(32, 64);

  // Note: In real implementation, RSA keys would be derived or stored
  // For now, we'll need to regenerate them or handle this differently
  throw new Error(
    'Master key reconstruction from shares requires RSA key regeneration. ' +
    'Use a proper SSS library that handles the full key material.'
  );
}

/**
 * Generate random session ID
 */
function generateSessionId(): string {
  const array = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(array, (b) => b.toString(16).padStart(2, '0')).join('');
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
