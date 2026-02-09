/**
 * Vault SvelteKit Server Integration
 * 
 * Server-side utilities for SvelteKit applications.
 * 
 * @example
 * ```typescript
 * // hooks.server.ts
 * import { vaultAuth } from '@fantasticauth/svelte/server';
 * 
 * export const handle = vaultAuth({
 *   publicRoutes: ['/sign-in', '/sign-up'],
 *   apiUrl: 'https://api.vault.dev',
 *   tenantId: 'my-tenant'
 * });
 * ```
 */

export { vaultAuth, requireAuth, optionalAuth } from './auth.js';
export { vaultActions } from './actions.js';
export {
  vaultAuth as fantasticauthAuth,
} from './auth.js';
export {
  vaultActions as fantasticauthActions,
} from './actions.js';
export type { VaultHandle, VaultServerLoad } from './types.js';
