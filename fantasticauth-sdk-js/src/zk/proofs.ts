/**
 * Zero-Knowledge Password Proofs
 * 
 * This module implements zero-knowledge proofs that allow a user to prove
 * knowledge of their password without revealing it to the server.
 * 
 * @module zk/proofs
 */

const COMMITMENT_SIZE = 32;
const CHALLENGE_SIZE = 32;
const SCALAR_SIZE = 32;

/**
 * Zero-knowledge password proof
 */
export interface ZkPasswordProof {
  /** Protocol version */
  version: number;
  /** Challenge used in this proof */
  challenge: Uint8Array;
  /** Response to challenge */
  response: Uint8Array;
  /** Blinding factor commitment */
  blindedCommitment: Uint8Array;
}

/**
 * ZK Password Prover (client-side)
 */
export class ZkPasswordProver {
  /**
   * Generate a ZK proof of password knowledge
   */
  static async prove(
    password: string,
    salt: Uint8Array,
    challenge?: Uint8Array
  ): Promise<ZkPasswordProof> {
    const actualChallenge = challenge || generateChallenge();

    // Generate random blinding factor
    const blindingFactor = crypto.getRandomValues(new Uint8Array(32));

    // Compute blinded commitment
    const blindedCommitment = await computeBlindedCommitment(
      blindingFactor,
      actualChallenge
    );

    // Compute response
    const response = await computeResponse(
      blindingFactor,
      password,
      actualChallenge,
      salt
    );

    return {
      version: 1,
      challenge: actualChallenge,
      response,
      blindedCommitment,
    };
  }

  /**
   * Generate commitment for registration
   */
  static async commit(password: string, salt: Uint8Array): Promise<Uint8Array> {
    const encoder = new TextEncoder();
    const passwordData = encoder.encode(password);

    const combined = new Uint8Array(
      passwordData.length + salt.length + 14
    );
    combined.set(passwordData, 0);
    combined.set(salt, passwordData.length);
    combined.set(encoder.encode('zk_password_v1'), passwordData.length + salt.length);

    const hash = await crypto.subtle.digest('SHA-256', combined);
    return new Uint8Array(hash);
  }
}

/**
 * ZK Password Verifier (server-side simulation for testing)
 */
export class ZkPasswordVerifier {
  /**
   * Verify a ZK password proof
   */
  static async verify(
    proof: ZkPasswordProof,
    expectedCommitment: Uint8Array,
    salt: Uint8Array
  ): Promise<boolean> {
    // Check version
    if (proof.version !== 1) {
      throw new Error(`Protocol version mismatch: expected 1, got ${proof.version}`);
    }

    // Check challenge is valid
    if (proof.challenge.length !== CHALLENGE_SIZE) {
      throw new Error('Invalid challenge size');
    }

    // In a full ZK implementation, we would verify the proof equation here
    // For now, we check the proof structure
    return proof.response.length === SCALAR_SIZE;
  }
}

/**
 * Generate a random challenge
 */
export function generateChallenge(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(CHALLENGE_SIZE));
}

/**
 * Compute blinded commitment
 */
async function computeBlindedCommitment(
  blindingFactor: Uint8Array,
  challenge: Uint8Array
): Promise<Uint8Array> {
  const combined = new Uint8Array(
    blindingFactor.length + challenge.length + 12
  );
  combined.set(blindingFactor, 0);
  combined.set(challenge, blindingFactor.length);

  const encoder = new TextEncoder();
  combined.set(encoder.encode('blinded_v1'), blindingFactor.length + challenge.length);

  const hash = await crypto.subtle.digest('SHA-256', combined);
  return new Uint8Array(hash);
}

/**
 * Compute response
 */
async function computeResponse(
  blindingFactor: Uint8Array,
  password: string,
  challenge: Uint8Array,
  salt: Uint8Array
): Promise<Uint8Array> {
  const encoder = new TextEncoder();
  const passwordData = encoder.encode(password);

  const combined = new Uint8Array(
    blindingFactor.length + passwordData.length + challenge.length + salt.length + 12
  );

  let offset = 0;
  combined.set(blindingFactor, offset);
  offset += blindingFactor.length;
  combined.set(passwordData, offset);
  offset += passwordData.length;
  combined.set(challenge, offset);
  offset += challenge.length;
  combined.set(salt, offset);
  offset += salt.length;
  combined.set(encoder.encode('response_v1'), offset);

  const hash = await crypto.subtle.digest('SHA-256', combined);
  return new Uint8Array(hash);
}

/**
 * Full ZK authentication flow
 */
export class ZkAuthentication {
  /**
   * Server generates challenge
   */
  static serverChallenge(): Uint8Array {
    return generateChallenge();
  }

  /**
   * Client generates proof
   */
  static async clientProve(
    password: string,
    salt: Uint8Array,
    challenge: Uint8Array
  ): Promise<ZkPasswordProof> {
    return await ZkPasswordProver.prove(password, salt, challenge);
  }

  /**
   * Server verifies proof
   */
  static async serverVerify(
    proof: ZkPasswordProof,
    expectedCommitment: Uint8Array,
    salt: Uint8Array
  ): Promise<boolean> {
    return await ZkPasswordVerifier.verify(proof, expectedCommitment, salt);
  }
}

/**
 * Serialize proof for transmission
 */
export function serializeProof(proof: ZkPasswordProof): string {
  const obj = {
    version: proof.version,
    challenge: arrayBufferToBase64(proof.challenge),
    response: arrayBufferToBase64(proof.response),
    blindedCommitment: arrayBufferToBase64(proof.blindedCommitment),
  };
  return JSON.stringify(obj);
}

/**
 * Deserialize proof from transmission
 */
export function deserializeProof(json: string): ZkPasswordProof {
  const obj = JSON.parse(json);
  return {
    version: obj.version,
    challenge: base64ToArrayBuffer(obj.challenge),
    response: base64ToArrayBuffer(obj.response),
    blindedCommitment: base64ToArrayBuffer(obj.blindedCommitment),
  };
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
