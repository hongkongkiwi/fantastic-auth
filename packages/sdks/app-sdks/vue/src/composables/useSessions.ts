/**
 * useSessions Composable
 *
 * Composable for session management.
 *
 * @example
 * ```vue
 * <script setup lang="ts">
 * import { useSessions } from '@fantasticauth/vue';
 *
 * const { sessions, revokeSession, revokeAllOtherSessions, refresh } = useSessions();
 *
 * // Load sessions on mount
 * onMounted(() => {
 *   refresh();
 * });
 * </script>
 *
 * <template>
 *   <ul>
 *     <li v-for="session in sessions" :key="session.id">
 *       {{ session.userAgent }} - {{ session.location }}
 *       <button @click="revokeSession(session.id)">Revoke</button>
 *     </li>
 *   </ul>
 *   <button @click="revokeAllOtherSessions">Sign out all other devices</button>
 * </template>
 * ```
 */

import { ref, onMounted } from 'vue';
import type { Ref } from 'vue';
import { VaultApiClient } from '../api/client';
import { useVault } from '../plugin';
import type { UseSessionsReturn, SessionInfo, ApiError, VaultConfig } from '../types';

/**
 * Composable for session management.
 *
 * @returns Session management methods and state
 */
export function useSessions(): UseSessionsReturn {
  const vault = useVault();
  const sessions = ref<SessionInfo[]>([]);
  const isLoading = ref(false);
  const error = ref<ApiError | null>(null);

  // Create a temporary API client for session operations
  // In a real implementation, this would use the API client from the vault context
  const getApiClient = async (): Promise<VaultApiClient | null> => {
    const token = await vault.getToken();
    if (!token) return null;

    // This is a simplified approach - in production you'd want to
    // get the config from the vault context
    return new VaultApiClient({
      apiUrl: '', // Would come from context
      tenantId: '', // Would come from context
      sessionToken: token,
    });
  };

  const refresh = async () => {
    isLoading.value = true;
    error.value = null;
    try {
      const api = await getApiClient();
      if (api) {
        const list = await api.listSessions();
        sessions.value = list;
      }
    } catch (err) {
      error.value = err as ApiError;
      throw err;
    } finally {
      isLoading.value = false;
    }
  };

  const revokeSession = async (sessionId: string) => {
    isLoading.value = true;
    error.value = null;
    try {
      const api = await getApiClient();
      if (api) {
        await api.revokeSession(sessionId);
        sessions.value = sessions.value.filter(s => s.id !== sessionId);
      }
    } catch (err) {
      error.value = err as ApiError;
      throw err;
    } finally {
      isLoading.value = false;
    }
  };

  const revokeAllOtherSessions = async () => {
    isLoading.value = true;
    error.value = null;
    try {
      const api = await getApiClient();
      if (api) {
        await api.revokeAllSessions();
        // Refresh to get updated list (should only contain current session)
        await refresh();
      }
    } catch (err) {
      error.value = err as ApiError;
      throw err;
    } finally {
      isLoading.value = false;
    }
  };

  // Load sessions on mount if signed in
  onMounted(() => {
    if (vault.isSignedIn.value) {
      refresh();
    }
  });

  return {
    sessions,
    isLoading,
    error,
    revokeSession,
    revokeAllOtherSessions,
    refresh,
  };
}
