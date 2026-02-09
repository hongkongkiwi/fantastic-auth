/**
 * Session Stores
 * 
 * Svelte stores and runes for session management.
 */

import { getVaultContext } from '../context.js';
import type { SessionInfo, ApiError } from '../types.js';

/**
 * useSession - Svelte 5 rune for session state
 * 
 * @example
 * ```svelte
 * <script>
 *   import { useSession } from '@vault/svelte';
 *   const { session, getToken, refresh } = useSession();
 * </script>
 * 
 * {#if session}
 *   <p>Session expires: {session.expiresAt}</p>
 * {/if}
 * ```
 */
export function useSession() {
  const vault = getVaultContext();
  
  return {
    get session() {
      let value = $state<ReturnType<typeof vault.session.subscribe> extends { subscribe(fn: (v: infer V) => void): () => void } ? V : never | null>(null);
      vault.session.subscribe(v => value = v)();
      return value;
    },
    get isLoaded() {
      let value = $state(false);
      vault.isLoaded.subscribe(v => value = v)();
      return value;
    },
    getToken: vault.getToken,
    refresh: vault.refreshSession,
  };
}

/**
 * useSessions - Manage all user sessions
 * 
 * @example
 * ```svelte
 * <script>
 *   import { useSessions } from '@vault/svelte';
 *   const { sessions, revokeSession, revokeAllOther } = useSessions();
 * </script>
 * 
 * <ul>
 *   {#each sessions as session}
 *     <li>
 *       {session.userAgent} - {session.location}
 *       {#if session.isCurrent}
 *         <span>(Current)</span>
 *       {:else}
 *         <button onclick={() => revokeSession(session.id)}>Revoke</button>
 *       {/if}
 *     </li>
 *   {/each}
 * </ul>
 * <button onclick={revokeAllOther}>Revoke All Other Sessions</button>
 * ```
 */
export function useSessions() {
  const vault = getVaultContext();
  
  let isLoading = $state(false);
  let error = $state<ApiError | null>(null);
  
  async function refresh(): Promise<void> {
    isLoading = true;
    error = null;
    try {
      await vault.refreshSessions();
    } catch (e) {
      error = e as ApiError;
      throw e;
    } finally {
      isLoading = false;
    }
  }
  
  async function revokeSession(sessionId: string): Promise<void> {
    isLoading = true;
    error = null;
    try {
      await vault.revokeSession(sessionId);
    } catch (e) {
      error = e as ApiError;
      throw e;
    } finally {
      isLoading = false;
    }
  }
  
  async function revokeAllOther(): Promise<void> {
    isLoading = true;
    error = null;
    try {
      await vault.revokeAllOtherSessions();
    } catch (e) {
      error = e as ApiError;
      throw e;
    } finally {
      isLoading = false;
    }
  }
  
  // Load sessions on mount
  $effect(() => {
    refresh();
  });
  
  return {
    get sessions() {
      let value = $state<SessionInfo[]>([]);
      vault.sessions.subscribe(v => value = v)();
      return value;
    },
    get isLoading() { return isLoading; },
    get error() { return error; },
    refresh,
    revokeSession,
    revokeAllOther,
  };
}
