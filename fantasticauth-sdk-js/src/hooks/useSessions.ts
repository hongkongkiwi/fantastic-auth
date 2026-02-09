/**
 * useSessions Hook
 * 
 * Hook for managing all user sessions with polling support.
 * 
 * @example
 * ```tsx
 * function SessionManager() {
 *   const { sessions, isLoading, revokeSession, revokeAllOtherSessions } = useSessions();
 *   
 *   return (
 *     <div>
 *       <h3>Active Sessions</h3>
 *       {sessions.map(session => (
 *         <SessionItem 
 *           key={session.id} 
 *           session={session}
 *           onRevoke={() => revokeSession(session.id)}
 *         />
 *       ))}
 *       <button onClick={revokeAllOtherSessions}>
 *         Sign out all other devices
 *       </button>
 *     </div>
 *   );
 * }
 * ```
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import { useVault } from '../context/VaultContext';
import { SessionInfo, UseSessionsReturn, ApiError } from '../types';

const DEFAULT_POLLING_INTERVAL = 30000; // 30 seconds

/**
 * Hook for managing all user sessions.
 * Automatically polls for session updates every 30 seconds when user is signed in.
 * 
 * @param options - Optional configuration for polling
 * @param options.pollingInterval - Custom polling interval in milliseconds (default: 30000)
 * @returns Session management functions and state
 */
export function useSessions(options?: { pollingInterval?: number }): UseSessionsReturn {
  const vault = useVault();
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const pollingInterval = options?.pollingInterval ?? DEFAULT_POLLING_INTERVAL;
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const refresh = useCallback(async () => {
    if (!vault.isSignedIn) {
      return;
    }

    setIsLoading(true);
    setError(null);
    try {
      await vault.refreshSessions();
    } catch (err) {
      setError(err as ApiError);
    } finally {
      setIsLoading(false);
    }
  }, [vault]);

  const revokeSession = useCallback(async (sessionId: string) => {
    setIsLoading(true);
    setError(null);
    try {
      await vault.revokeSession(sessionId);
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
      await vault.revokeAllOtherSessions();
    } catch (err) {
      setError(err as ApiError);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [vault]);

  // Initial load and polling setup
  useEffect(() => {
    // Load sessions immediately when signed in
    if (vault.isSignedIn) {
      refresh();
    }

    // Set up polling
    if (vault.isSignedIn && pollingInterval > 0) {
      pollingRef.current = setInterval(() => {
        vault.refreshSessions();
      }, pollingInterval);
    }

    return () => {
      if (pollingRef.current) {
        clearInterval(pollingRef.current);
        pollingRef.current = null;
      }
    };
  }, [vault.isSignedIn, pollingInterval, vault.refreshSessions]);

  return {
    sessions: vault.sessions,
    isLoading,
    error,
    revokeSession,
    revokeAllOtherSessions,
    refresh,
  };
}

/**
 * Hook to get the list of all active sessions.
 * 
 * @returns Array of session info objects
 */
export function useSessionList(): SessionInfo[] {
  const vault = useVault();
  return vault.sessions;
}

/**
 * Hook to check if there are other active sessions besides the current one.
 * 
 * @returns Boolean indicating if other sessions exist
 */
export function useHasOtherSessions(): boolean {
  const vault = useVault();
  return vault.sessions.some(s => !s.isCurrent);
}

/**
 * Hook to get the current session info.
 * 
 * @returns The current session info or null
 */
export function useCurrentSession(): SessionInfo | null {
  const vault = useVault();
  return vault.sessions.find(s => s.isCurrent) || null;
}
