/**
 * useSession Hook
 * 
 * Hook for session management.
 * 
 * @example
 * ```tsx
 * function App() {
 *   const { session, getToken } = useSession();
 *   
 *   useEffect(() => {
 *     // Get token for API calls
 *     getToken().then(token => {
 *       // Use token for external API calls
 *     });
 *   }, []);
 * }
 * ```
 */

import { useVault } from '../context/VaultContext';
import { UseSessionReturn } from '../types';

/**
 * Hook to access the current session.
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
