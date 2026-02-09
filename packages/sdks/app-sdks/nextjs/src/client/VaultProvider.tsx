'use client';

/**
 * VaultProvider - Client-side provider for Vault authentication
 * 
 * Wraps your app with authentication context and handles session management.
 * 
 * @example
 * ```tsx
 * // app/layout.tsx
 * import { VaultProvider } from '@fantasticauth/nextjs';
 * 
 * export default function RootLayout({ children }) {
 *   return (
 *     <VaultProvider 
 *       apiUrl={process.env.NEXT_PUBLIC_VAULT_API_URL}
 *       tenantId={process.env.NEXT_PUBLIC_VAULT_TENANT_ID}
 *       publishableKey={process.env.NEXT_PUBLIC_VAULT_PUBLISHABLE_KEY}
 *     >
 *       {children}
 *     </VaultProvider>
 *   );
 * }
 * ```
 */

import * as React from 'react';
import type { VaultProviderConfig, User, Session } from '../types';
import { decodeToken, isTokenExpired } from '../server/authClient';

// Cookie names
const SESSION_COOKIE_NAME = '__fantasticauth_session';
const REFRESH_COOKIE_NAME = '__fantasticauth_refresh';
const LEGACY_SESSION_COOKIE_NAME = '__vault_session';
const LEGACY_REFRESH_COOKIE_NAME = '__vault_refresh';

function getApiBase(apiUrl: string): string {
  const normalized = apiUrl.replace(/\/$/, '');
  return normalized.endsWith('/api') ? normalized : `${normalized}/api`;
}

// Context types
interface VaultContextValue {
  isLoaded: boolean;
  isSignedIn: boolean;
  user: User | null;
  session: Session | null;
  orgId: string | null;
  orgRole: string | null;
  signOut: () => Promise<void>;
  getToken: () => Promise<string | null>;
}

const VaultContext = React.createContext<VaultContextValue | null>(null);

/**
 * Hook to use the Vault context
 */
export function useVaultContext(): VaultContextValue {
  const context = React.useContext(VaultContext);
  if (!context) {
    throw new Error('useVaultContext must be used within a VaultProvider');
  }
  return context;
}

// Internal state type
interface AuthState {
  isLoaded: boolean;
  isSignedIn: boolean;
  user: User | null;
  session: Session | null;
  orgId: string | null;
  orgRole: string | null;
}

export interface VaultProviderProps extends VaultProviderConfig {
  children: React.ReactNode;
  /**
   * Initial auth state from server (for SSR hydration)
   */
  initialState?: Partial<AuthState>;
  /**
   * Called when authentication state changes
   */
  onAuthStateChange?: (state: AuthState) => void;
}

/**
 * Get cookie value by name
 */
function getCookie(name: string): string | null {
  if (typeof document === 'undefined') {
    return null;
  }
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) {
    return parts.pop()?.split(';').shift() || null;
  }
  return null;
}

/**
 * Set cookie value
 */
function setCookie(
  name: string,
  value: string,
  options: { maxAge?: number; path?: string; secure?: boolean; sameSite?: string } = {}
): void {
  if (typeof document === 'undefined') {
    return;
  }
  const { maxAge = 60 * 60 * 24 * 7, path = '/', secure, sameSite = 'lax' } = options;
  let cookieString = `${name}=${value}; path=${path}; max-age=${maxAge}; SameSite=${sameSite}`;
  if (secure || window.location.protocol === 'https:') {
    cookieString += '; Secure';
  }
  document.cookie = cookieString;
}

/**
 * Delete cookie
 */
function deleteCookie(name: string): void {
  if (typeof document === 'undefined') {
    return;
  }
  document.cookie = `${name}=; path=/; max-age=0; SameSite=Lax`;
}

function getAuthCookie(
  primaryName: string,
  legacyName: string
): string | null {
  return getCookie(primaryName) || getCookie(legacyName);
}

function setAuthCookie(
  primaryName: string,
  legacyName: string,
  value: string,
  options: { maxAge?: number; path?: string; secure?: boolean; sameSite?: string } = {}
): void {
  setCookie(primaryName, value, options);
  deleteCookie(legacyName);
}

function clearAuthCookies(): void {
  deleteCookie(SESSION_COOKIE_NAME);
  deleteCookie(REFRESH_COOKIE_NAME);
  deleteCookie(LEGACY_SESSION_COOKIE_NAME);
  deleteCookie(LEGACY_REFRESH_COOKIE_NAME);
}

/**
 * Fetch user data from API
 */
async function fetchUser(apiUrl: string, tenantId: string, token: string): Promise<User | null> {
  try {
    const response = await fetch(`${getApiBase(apiUrl)}/v1/users/me`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'X-Tenant-ID': tenantId,
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      return null;
    }

    const data = await response.json();
    return data.user as User;
  } catch {
    return null;
  }
}

/**
 * Refresh session using refresh token
 */
async function refreshSession(
  apiUrl: string,
  tenantId: string,
  refreshToken: string
): Promise<{ token: string; refreshToken: string; user: User } | null> {
  try {
    const response = await fetch(`${getApiBase(apiUrl)}/v1/auth/refresh`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Tenant-ID': tenantId,
      },
      body: JSON.stringify({ refreshToken }),
    });

    if (!response.ok) {
      return null;
    }

    const data = await response.json();
    return {
      token: data.token,
      refreshToken: data.refreshToken,
      user: data.user as User,
    };
  } catch {
    return null;
  }
}

/**
 * VaultProvider component
 */
export function VaultProvider({
  children,
  apiUrl,
  tenantId,
  publishableKey,
  debug = false,
  sessionLifetime = 60 * 60 * 24 * 7, // 7 days
  initialState,
  onAuthStateChange,
}: VaultProviderProps): React.ReactElement {
  const [state, setState] = React.useState<AuthState>({
    isLoaded: false,
    isSignedIn: false,
    user: null,
    session: null,
    orgId: null,
    orgRole: null,
    ...initialState,
  });

  const debugLog = React.useCallback(
    (...args: unknown[]) => {
      if (debug) {
        console.log('[Vault]', ...args);
      }
    },
    [debug]
  );

  // Initialize auth state
  React.useEffect(() => {
    const initAuth = async () => {
      debugLog('Initializing auth state');

      const token = getAuthCookie(SESSION_COOKIE_NAME, LEGACY_SESSION_COOKIE_NAME);
      const refreshToken = getAuthCookie(REFRESH_COOKIE_NAME, LEGACY_REFRESH_COOKIE_NAME);

      if (!token) {
        debugLog('No session token found');
        setState((prev) => ({ ...prev, isLoaded: true }));
        return;
      }

      // Check if token is expired
      if (isTokenExpired(token)) {
        debugLog('Token expired, attempting refresh');

        if (refreshToken) {
          const refreshed = await refreshSession(apiUrl, tenantId, refreshToken);

          if (refreshed) {
            debugLog('Session refreshed successfully');

            // Update cookies
            setAuthCookie(SESSION_COOKIE_NAME, LEGACY_SESSION_COOKIE_NAME, refreshed.token, { maxAge: sessionLifetime });
            if (refreshed.refreshToken) {
              setAuthCookie(REFRESH_COOKIE_NAME, LEGACY_REFRESH_COOKIE_NAME, refreshed.refreshToken, {
                maxAge: sessionLifetime * 4, // Refresh tokens last longer
              });
            }

            // Decode token for session info
            const decoded = decodeToken(refreshed.token);

            const newState: AuthState = {
              isLoaded: true,
              isSignedIn: true,
              user: refreshed.user,
              session: {
                id: decoded?.sid || '',
                userId: refreshed.user.id,
                token: refreshed.token,
                expiresAt: decoded?.exp
                  ? new Date(decoded.exp * 1000)
                  : new Date(Date.now() + sessionLifetime * 1000),
              },
              orgId: decoded?.org_id || null,
              orgRole: decoded?.org_role || null,
            };

            setState(newState);
            onAuthStateChange?.(newState);
            return;
          }
        }

        // Refresh failed, clear cookies
        debugLog('Token refresh failed');
        clearAuthCookies();
        setState({
          isLoaded: true,
          isSignedIn: false,
          user: null,
          session: null,
          orgId: null,
          orgRole: null,
        });
        return;
      }

      // Token is valid, fetch user data
      debugLog('Token valid, fetching user');
      const user = await fetchUser(apiUrl, tenantId, token);
      const decoded = decodeToken(token);

      if (user && decoded) {
        debugLog('User fetched successfully');
        const newState: AuthState = {
          isLoaded: true,
          isSignedIn: true,
          user,
          session: {
            id: decoded.sid,
            userId: user.id,
            token,
            expiresAt: decoded.exp
              ? new Date(decoded.exp * 1000)
              : new Date(Date.now() + sessionLifetime * 1000),
          },
          orgId: decoded.org_id || null,
          orgRole: decoded.org_role || null,
        };

        setState(newState);
        onAuthStateChange?.(newState);
      } else {
        debugLog('Failed to fetch user, clearing session');
        clearAuthCookies();
        setState({
          isLoaded: true,
          isSignedIn: false,
          user: null,
          session: null,
          orgId: null,
          orgRole: null,
        });
      }
    };

    initAuth();
  }, [apiUrl, tenantId, sessionLifetime, debugLog, onAuthStateChange]);

  // Set up token refresh interval
  React.useEffect(() => {
    if (!state.isSignedIn || !state.session) {
      return;
    }

    const checkAndRefreshToken = async () => {
      const token = getAuthCookie(SESSION_COOKIE_NAME, LEGACY_SESSION_COOKIE_NAME);

      if (!token || isTokenExpired(token)) {
        debugLog('Token expiring, refreshing...');
        const refreshToken = getAuthCookie(REFRESH_COOKIE_NAME, LEGACY_REFRESH_COOKIE_NAME);

        if (refreshToken) {
          const refreshed = await refreshSession(apiUrl, tenantId, refreshToken);

          if (refreshed) {
            setAuthCookie(SESSION_COOKIE_NAME, LEGACY_SESSION_COOKIE_NAME, refreshed.token, { maxAge: sessionLifetime });
            if (refreshed.refreshToken) {
              setAuthCookie(REFRESH_COOKIE_NAME, LEGACY_REFRESH_COOKIE_NAME, refreshed.refreshToken, {
                maxAge: sessionLifetime * 4,
              });
            }

            const decoded = decodeToken(refreshed.token);
            setState((prev) => ({
              ...prev,
              user: refreshed.user,
              session: decoded
                ? {
                    id: decoded.sid,
                    userId: refreshed.user.id,
                    token: refreshed.token,
                    expiresAt: decoded.exp
                      ? new Date(decoded.exp * 1000)
                      : new Date(Date.now() + sessionLifetime * 1000),
                  }
                : prev.session,
              orgId: decoded?.org_id || prev.orgId,
              orgRole: decoded?.org_role || prev.orgRole,
            }));
          }
        }
      }
    };

    // Check every 5 minutes
    const interval = setInterval(checkAndRefreshToken, 5 * 60 * 1000);

    return () => clearInterval(interval);
  }, [state.isSignedIn, state.session, apiUrl, tenantId, sessionLifetime, debugLog]);

  // Sign out function
  const signOut = React.useCallback(async (): Promise<void> => {
    debugLog('Signing out');

    const token = getAuthCookie(SESSION_COOKIE_NAME, LEGACY_SESSION_COOKIE_NAME);

    // Call sign out API
    if (token) {
      try {
        await fetch(`${getApiBase(apiUrl)}/v1/auth/signout`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
            'X-Tenant-ID': tenantId,
            'Content-Type': 'application/json',
          },
        });
      } catch (error) {
        debugLog('Sign out API error:', error);
      }
    }

    // Clear cookies
    clearAuthCookies();

    // Update state
    const newState: AuthState = {
      isLoaded: true,
      isSignedIn: false,
      user: null,
      session: null,
      orgId: null,
      orgRole: null,
    };

    setState(newState);
    onAuthStateChange?.(newState);

    // Reload page to clear any server state
    window.location.href = '/';
  }, [apiUrl, tenantId, debugLog, onAuthStateChange]);

  // Get token function
  const getToken = React.useCallback(async (): Promise<string | null> => {
    const token = getAuthCookie(SESSION_COOKIE_NAME, LEGACY_SESSION_COOKIE_NAME);

    if (!token) {
      return null;
    }

    // Check if token needs refresh
    if (isTokenExpired(token)) {
      const refreshToken = getAuthCookie(REFRESH_COOKIE_NAME, LEGACY_REFRESH_COOKIE_NAME);

      if (refreshToken) {
        const refreshed = await refreshSession(apiUrl, tenantId, refreshToken);

        if (refreshed) {
          setAuthCookie(SESSION_COOKIE_NAME, LEGACY_SESSION_COOKIE_NAME, refreshed.token, { maxAge: sessionLifetime });
          if (refreshed.refreshToken) {
            setAuthCookie(REFRESH_COOKIE_NAME, LEGACY_REFRESH_COOKIE_NAME, refreshed.refreshToken, {
              maxAge: sessionLifetime * 4,
            });
          }
          return refreshed.token;
        }
      }

      return null;
    }

    return token;
  }, [apiUrl, tenantId, sessionLifetime]);

  const contextValue: VaultContextValue = {
    isLoaded: state.isLoaded,
    isSignedIn: state.isSignedIn,
    user: state.user,
    session: state.session,
    orgId: state.orgId,
    orgRole: state.orgRole,
    signOut,
    getToken,
  };

  return (
    <VaultContext.Provider value={contextValue}>
      {children}
    </VaultContext.Provider>
  );
}

export const FantasticauthProvider = VaultProvider;
export const useFantasticauthContext = useVaultContext;
export type FantasticauthProviderProps = VaultProviderProps;
