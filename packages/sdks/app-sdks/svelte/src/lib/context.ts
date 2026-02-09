/**
 * Vault Context
 * 
 * Svelte context for Vault authentication state and methods.
 * Provides both Svelte 4 (getContext) and Svelte 5 (runes) compatible APIs.
 */

import { getContext } from 'svelte';
import type { VaultContextValue } from './types.js';

// Context key symbol for secure context access
export const VAULT_CONTEXT_KEY = Symbol('vault');
export const FANTASTICAUTH_CONTEXT_KEY = VAULT_CONTEXT_KEY;

/**
 * Get the Vault context value.
 * Must be used within a VaultProvider.
 * 
 * @example
 * ```svelte
 * <script>
 *   import { getVaultContext } from '@fantasticauth/svelte';
 *   const vault = getVaultContext();
 * </script>
 * 
 * {#if $vault.isSignedIn}
 *   <p>Welcome {$vault.user?.email}</p>
 * {/if}
 * ```
 */
export function getVaultContext(): VaultContextValue {
  const context = getContext<VaultContextValue>(VAULT_CONTEXT_KEY);
  
  if (!context) {
    throw new Error('getVaultContext must be used within a VaultProvider');
  }
  
  return context;
}

export function getFantasticauthContext(): VaultContextValue {
  return getVaultContext();
}

/**
 * Check if the Vault context is available.
 * Useful for conditional logic in components.
 * 
 * @example
 * ```svelte
 * <script>
 *   import { hasVaultContext } from '@fantasticauth/svelte';
 *   
 *   const hasVault = hasVaultContext();
 * </script>
 * 
 * {#if hasVault}
 *   <AuthenticatedContent />
 * {:else}
 *   <p>Vault not configured</p>
 * {/if}
 * ```
 */
export function hasVaultContext(): boolean {
  try {
    const context = getContext<VaultContextValue>(VAULT_CONTEXT_KEY);
    return !!context;
  } catch {
    return false;
  }
}

export function hasFantasticauthContext(): boolean {
  return hasVaultContext();
}
