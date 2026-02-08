/**
 * useSession Hook
 * 
 * Hook for session management in React Native.
 * Includes automatic refresh handling.
 * 
 * @example
 * ```tsx
 * function SecureApiCall() {
 *   const { getToken, refresh, lastRefreshedAt } = useSession();
 *   
 *   const makeApiCall = async () => {
 *     const token = await getToken();
 *     // Use token for external API calls
 *   };
 *   
 *   return (
 *     <View>
 *       <Text>Last refreshed: {new Date(lastRefreshedAt || 0).toLocaleString()}</Text>
 *       <Button onPress={makeApiCall}>Make API Call</Button>
 *       <Button onPress={refresh}>Refresh Session</Button>
 *     </View>
 *   );
 * }
 * ```
 */

import { useState, useEffect, useCallback } from 'react';
import { useVault } from '../VaultProvider';
import { UseSessionReturn, ApiError, SessionInfo } from '../types';
import { AppState } from 'react-native';

/**
 * Hook to access the current session.
 * 
 * @returns Session data and methods
 */
export function useSession(): UseSessionReturn {
  const vault = useVault();
  const [lastRefreshedAt, setLastRefreshedAt] = useState<number | null>(null);

  // Refresh session when app comes to foreground
  useEffect(() => {
    const subscription = AppState.addEventListener('change', (nextAppState) => {
      if (nextAppState === 'active') {
        // App came to foreground, refresh session if needed
        const shouldRefresh = !lastRefreshedAt || 
          (Date.now() - lastRefreshedAt > 5 * 60 * 1000); // 5 minutes
        
        if (shouldRefresh && vault.isSignedIn) {
          vault.refreshSession().then(() => {
            setLastRefreshedAt(Date.now());
          }).catch(() => {
            // Session refresh failed, user will be signed out
          });
        }
      }
    });

    return () => {
      subscription.remove();
    };
  }, [vault, lastRefreshedAt]);

  const refresh = useCallback(async () => {
    await vault.refreshSession();
    setLastRefreshedAt(Date.now());
  }, [vault]);

  return {
    session: vault.session,
    isLoaded: vault.isLoaded,
    getToken: vault.getToken,
    refresh,
    lastRefreshedAt,
  };
}

/**
 * Hook to get the session token.
 * Useful for making authenticated API calls.
 * 
 * @returns Function to get the current token
 */
export function useToken(): () => Promise<string | null> {
  const vault = useVault();
  return vault.getToken;
}

/**
 * Hook to get the current session ID.
 * 
 * @returns The current session ID or null
 */
export function useSessionId(): string | null {
  const vault = useVault();
  return vault.session?.id || null;
}

/**
 * Hook for managing multiple sessions (active devices).
 * 
 * @example
 * ```tsx
 * function SessionManager() {
 *   const { sessions, revokeSession, revokeAllOtherSessions } = useSessions();
 *   
 *   return (
 *     <View>
 *       {sessions.map(session => (
 *         <SessionItem 
 *           key={session.id} 
 *           session={session}
 *           onRevoke={() => revokeSession(session.id)}
 *         />
 *       ))}
 *       <Button onPress={revokeAllOtherSessions}>
 *         Sign out all other devices
 *       </Button>
 *     </View>
 *   );
 * }
 * ```
 */
export function useSessions(): {
  sessions: SessionInfo[];
  isLoading: boolean;
  error: ApiError | null;
  revokeSession: (sessionId: string) => Promise<void>;
  revokeAllOtherSessions: () => Promise<void>;
  refresh: () => Promise<void>;
} {
  const vault = useVault();
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [sessions, setSessions] = useState<SessionInfo[]>([]);

  const refresh = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const sessionsList = await vault.api.listSessions();
      setSessions(sessionsList);
    } catch (err) {
      setError(err as ApiError);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [vault]);

  const revokeSession = useCallback(async (sessionId: string) => {
    setIsLoading(true);
    setError(null);
    try {
      await vault.api.revokeSession(sessionId);
      setSessions(prev => prev.filter(s => s.id !== sessionId));
    } catch (err) {
      setError(err as ApiError);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [vault]);

  const revokeAllOtherSessions = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      await vault.api.revokeAllSessions();
      // Refresh to get updated list (should only contain current session)
      await refresh();
    } catch (err) {
      setError(err as ApiError);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [refresh, vault]);

  // Load sessions on mount
  useEffect(() => {
    if (vault.isSignedIn) {
      refresh();
    }
  }, [vault.isSignedIn]);

  return {
    sessions,
    isLoading,
    error,
    revokeSession,
    revokeAllOtherSessions,
    refresh,
  };
}
