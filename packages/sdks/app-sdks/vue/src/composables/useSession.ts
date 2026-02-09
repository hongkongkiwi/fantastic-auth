/**
 * useSession Composable
 *
 * Composable for session management.
 *
 * @example
 * ```vue
 * <script setup lang="ts">
 * import { onMounted } from 'vue';
 * import { useSession } from '@fantasticauth/vue';
 *
 * const { session, getToken } = useSession();
 *
 * onMounted(async () => {
 *   // Get token for API calls
 *   const token = await getToken();
 *   // Use token for external API calls
 * });
 * </script>
 *
 * <template>
 *   <div v-if="session">
 *     <p>Session expires: {{ session.expiresAt }}</p>
 *   </div>
 * </template>
 * ```
 */

import { useVault } from '../plugin';
import type { UseSessionReturn } from '../types';

/**
 * Composable to access the current session.
 *
 * @returns Session data and methods
 */
export function useSession(): UseSessionReturn {
  const vault = useVault();

  return {
    session: vault.session,
    isLoaded: vault.isLoaded,
    getToken: vault.getToken,
    refresh: vault.refreshSession,
  };
}

/**
 * Composable to get the session token.
 * Useful for making authenticated API calls.
 *
 * @returns Function to get the current token
 */
export function useToken(): () => Promise<string | null> {
  const vault = useVault();
  return vault.getToken;
}

/**
 * Composable to get the current session ID.
 *
 * @returns The current session ID or null
 */
export function useSessionId(): string | null {
  const vault = useVault();
  return vault.session.value?.id || null;
}
