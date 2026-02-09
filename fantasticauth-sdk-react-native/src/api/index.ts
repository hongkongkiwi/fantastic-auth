/**
 * API Client Module
 * 
 * HTTP client for the Vault API, adapted for React Native with secure storage.
 * 
 * @example
 * ```typescript
 * import { createVaultClient, VaultApiClient } from '@vault/react-native';
 * 
 * const client = createVaultClient({
 *   apiUrl: 'https://api.vault.dev',
 *   tenantId: 'my-tenant'
 * });
 * 
 * // Sign in
 * const { user, session } = await client.signIn({
 *   email: 'user@example.com',
 *   password: 'password'
 * });
 * 
 * // Refresh session
 * const newSession = await client.refreshSessionWithDedup();
 * ```
 */

export {
  VaultApiClient,
  createVaultClient,
  getGlobalClient,
  setGlobalClient,
  clearGlobalClient,
} from './client';
