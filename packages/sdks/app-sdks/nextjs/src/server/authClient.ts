/**
 * Authentication client for server-side operations
 * Works in both Node.js and Edge runtimes
 */

import { jwtVerify, importSPKI, importJWK } from 'jose';
import type { TokenValidationResult, VaultJwtClaims } from '../types';

function getApiBase(apiUrl: string): string {
  const normalized = apiUrl.replace(/\/$/, '');
  return normalized.endsWith('/api') ? normalized : `${normalized}/api`;
}

/**
 * Create an auth client for server-side API calls
 */
export function createAuthClient(apiUrl: string, tenantId: string) {
  const apiBase = getApiBase(apiUrl);

  return {
    /**
     * Validate a session token via the Vault API
     */
    async validateSession(token: string): Promise<TokenValidationResult> {
      try {
        const response = await fetch(`${apiBase}/v1/auth/validate`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Tenant-ID': tenantId,
          },
          body: JSON.stringify({ token }),
        });

        if (!response.ok) {
          const error = await response.json().catch(() => ({}));
          return {
            valid: false,
            error: error.message || 'Invalid session',
          };
        }

        const data = await response.json();
        return {
          valid: true,
          userId: data.userId,
          sessionId: data.sessionId,
          orgId: data.orgId,
          orgRole: data.orgRole,
          expiresAt: data.expiresAt,
        };
      } catch (error) {
        return {
          valid: false,
          error: error instanceof Error ? error.message : 'Validation failed',
        };
      }
    },

    /**
     * Refresh a session using a refresh token
     */
    async refreshSession(refreshToken: string): Promise<{ token: string; refreshToken: string } | null> {
      try {
        const response = await fetch(`${apiBase}/v1/auth/refresh`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Tenant-ID': tenantId,
          },
          body: JSON.stringify({ refreshToken }),
        });

        if (!response.ok) {
          return null;
        }

        const data = await response.json();
        return {
          token: data.token,
          refreshToken: data.refreshToken,
        };
      } catch {
        return null;
      }
    },

    /**
     * Get user by ID
     */
    async getUser(userId: string, token: string) {
      const response = await fetch(`${apiBase}/v1/users/${userId}`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'X-Tenant-ID': tenantId,
        },
      });

      if (!response.ok) {
        throw new Error(`Failed to get user: ${response.statusText}`);
      }

      return response.json();
    },
  };
}

/**
 * Verify a JWT token
 * Works in both Node.js and Edge runtimes
 */
export async function verifyToken(
  token: string,
  secretOrKey: string
): Promise<TokenValidationResult> {
  try {
    // Try to import as JWK first, then as PEM
    let key;
    try {
      const jwk = JSON.parse(secretOrKey);
      key = await importJWK(jwk, 'RS256');
    } catch {
      // Not a JWK, try as PEM
      try {
        key = await importSPKI(secretOrKey, 'RS256');
      } catch {
        // Try as symmetric key (for development/testing)
        key = new TextEncoder().encode(secretOrKey);
      }
    }

    const { payload } = await jwtVerify(token, key, {
      algorithms: ['RS256', 'HS256'],
    });

    // Validate required claims
    if (!payload.sub || !payload.sid) {
      return {
        valid: false,
        error: 'Invalid token claims',
      };
    }

    return {
      valid: true,
      userId: payload.sub,
      sessionId: payload.sid as string,
      orgId: payload.org_id as string | undefined,
      orgRole: payload.org_role as string | undefined,
      expiresAt: payload.exp,
    };
  } catch (error) {
    return {
      valid: false,
      error: error instanceof Error ? error.message : 'Token verification failed',
    };
  }
}

/**
 * Decode a token without verification (for debugging/client-side)
 */
export function decodeToken(token: string): VaultJwtClaims | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return null;
    }

    const payload = JSON.parse(
      atob(parts[1].replace(/-/g, '+').replace(/_/g, '/'))
    );

    return payload as VaultJwtClaims;
  } catch {
    return null;
  }
}

/**
 * Check if a token is expired
 */
export function isTokenExpired(token: string): boolean {
  const decoded = decodeToken(token);
  if (!decoded || !decoded.exp) {
    return true;
  }

  // Add 30 second buffer
  return decoded.exp * 1000 < Date.now() + 30000;
}

/**
 * Get token expiration time
 */
export function getTokenExpiration(token: string): Date | null {
  const decoded = decodeToken(token);
  if (!decoded || !decoded.exp) {
    return null;
  }

  return new Date(decoded.exp * 1000);
}
