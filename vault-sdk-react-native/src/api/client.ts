/**
 * Vault React Native API Client
 * 
 * HTTP client for the Vault API, adapted for React Native.
 * Features secure token storage, session refresh, and offline support.
 */

import { Platform } from 'react-native';
import { 
  VaultApiClient as BaseVaultApiClient,
  createVaultClient as createBaseVaultClient,
} from '@vault/react';
import { VaultConfig, User, Session, ApiError } from '../types';
import {
  storeSessionToken,
  getSessionToken,
  storeRefreshToken,
  getRefreshToken,
  clearSessionTokens,
  storeCachedUser,
  getCachedUser,
} from '../storage';

// ============================================================================
// React Native API Client
// ============================================================================

export class VaultApiClient extends BaseVaultApiClient {
  private refreshPromise: Promise<Session> | null = null;
  private lastRefreshTime: number = 0;
  private readonly minRefreshInterval: number = 60000; // 1 minute

  constructor(config: VaultConfig) {
    super(config);
  }

  // ============================================================================
  // Token Management (Override to use secure storage)
  // ============================================================================

  async storeToken(token: string): Promise<void> {
    await storeSessionToken(token);
  }

  async getStoredToken(): Promise<string | null> {
    return getSessionToken();
  }

  async storeRefreshToken(token: string): Promise<void> {
    await storeRefreshToken(token);
  }

  async getStoredRefreshToken(): Promise<string | null> {
    return getRefreshToken();
  }

  async clearToken(): Promise<void> {
    await clearSessionTokens();
  }

  // ============================================================================
  // Session Refresh with Deduplication
  // ============================================================================

  /**
   * Refresh session with deduplication to prevent multiple concurrent refreshes
   */
  async refreshSessionWithDedup(): Promise<Session> {
    // Check if refresh is already in progress
    if (this.refreshPromise) {
      return this.refreshPromise;
    }

    // Check if we refreshed recently
    const now = Date.now();
    if (now - this.lastRefreshTime < this.minRefreshInterval) {
      const token = await this.getStoredToken();
      if (token) {
        // Return cached session info
        return { accessToken: token } as Session;
      }
    }

    // Start new refresh
    this.refreshPromise = this.performRefresh()
      .then((session) => {
        this.lastRefreshTime = Date.now();
        this.refreshPromise = null;
        return session;
      })
      .catch((error) => {
        this.refreshPromise = null;
        throw error;
      });

    return this.refreshPromise;
  }

  private async performRefresh(): Promise<Session> {
    const refreshToken = await this.getStoredRefreshToken();
    
    if (!refreshToken) {
      throw new Error('No refresh token available');
    }

    const response = await this.request<{
      session: Session;
    }>('/api/v1/auth/refresh', {
      method: 'POST',
      body: JSON.stringify({ refreshToken }),
    });

    await this.storeToken(response.session.accessToken);
    if (response.session.refreshToken) {
      await this.storeRefreshToken(response.session.refreshToken);
    }

    return response.session;
  }

  // ============================================================================
  // Request with Automatic Retry
  // ============================================================================

  /**
   * Make an API request with automatic token refresh on 401 errors
   */
  async requestWithRetry<T>(
    endpoint: string, 
    options: RequestInit = {},
    maxRetries: number = 1
  ): Promise<T> {
    try {
      return await this.request<T>(endpoint, options);
    } catch (error: any) {
      // Check if error is 401 and we haven't exceeded retries
      if (error?.code === 'unauthorized' && maxRetries > 0) {
        try {
          await this.refreshSessionWithDedup();
          // Retry the request with new token
          return await this.request<T>(endpoint, options);
        } catch {
          // Refresh failed, clear tokens and throw
          await this.clearToken();
          throw error;
        }
      }
      throw error;
    }
  }

  // ============================================================================
  // Offline Support
  // ============================================================================

  /**
   * Cache user data for offline access
   */
  async cacheUserData(user: User): Promise<void> {
    await storeCachedUser(user);
  }

  /**
   * Get cached user data (for offline mode)
   */
  async getCachedUserData(): Promise<User | null> {
    return getCachedUser();
  }

  // ============================================================================
  // Biometric Authentication
  // ============================================================================

  /**
   * Sign in with biometric (uses pre-registered biometric credential)
   */
  async signInWithBiometric(challenge: string, signature: string): Promise<{
    user: User;
    session: Session;
  }> {
    return this.request('/api/v1/auth/biometric', {
      method: 'POST',
      body: JSON.stringify({ challenge, signature }),
    });
  }

  /**
   * Register biometric credential for future sign-ins
   */
  async registerBiometric(credentialId: string, publicKey: string): Promise<void> {
    await this.request('/api/v1/users/me/biometric', {
      method: 'POST',
      body: JSON.stringify({ credentialId, publicKey }),
    });
  }

  // ============================================================================
  // Push Notifications
  // ============================================================================

  /**
   * Register push notification token
   */
  async registerPushToken(token: string, platform: 'ios' | 'android' = Platform.OS as 'ios' | 'android'): Promise<void> {
    await this.request('/api/v1/users/me/push-token', {
      method: 'POST',
      body: JSON.stringify({ token, platform }),
    });
  }

  /**
   * Unregister push notification token
   */
  async unregisterPushToken(): Promise<void> {
    await this.request('/api/v1/users/me/push-token', {
      method: 'DELETE',
    });
  }
}

// ============================================================================
// Client Factory
// ============================================================================

/**
 * Create a new Vault API client for React Native
 */
export function createVaultClient(config: VaultConfig): VaultApiClient {
  return new VaultApiClient(config);
}

// ============================================================================
// Singleton Instance (for advanced use cases)
// ============================================================================

let globalClient: VaultApiClient | null = null;

/**
 * Get or create global API client instance
 */
export function getGlobalClient(config?: VaultConfig): VaultApiClient {
  if (!globalClient && config) {
    globalClient = createVaultClient(config);
  }
  
  if (!globalClient) {
    throw new Error('Vault client not initialized. Provide config or use VaultProvider.');
  }
  
  return globalClient;
}

/**
 * Set global client instance
 */
export function setGlobalClient(client: VaultApiClient): void {
  globalClient = client;
}

/**
 * Clear global client instance
 */
export function clearGlobalClient(): void {
  globalClient = null;
}
