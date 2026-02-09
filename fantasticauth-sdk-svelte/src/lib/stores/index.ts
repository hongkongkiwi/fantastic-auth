/**
 * Vault Svelte Stores
 * 
 * Svelte 4 compatible stores for Vault authentication state.
 * For Svelte 5, use the `useAuth()`, `useUser()`, etc. runes instead.
 * 
 * @example
 * ```svelte
 * <script>
 *   import { authStore, userStore } from '@vault/svelte/stores';
 * </script>
 * 
 * {#if $authStore.isSignedIn}
 *   <p>Welcome {$userStore.user?.email}</p>
 * {/if}
 * ```
 */

// Re-export all stores
export { authStore, userStore, sessionStore, organizationStore } from './auth.js';
export { useAuth, useSignIn, useSignUp, useAuthState, useRequireAuth } from './auth.js';
