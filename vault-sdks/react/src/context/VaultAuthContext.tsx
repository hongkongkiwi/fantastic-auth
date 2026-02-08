/**
 * Vault Auth Context
 * 
 * React context for Vault authentication with pre-built UI components.
 */

import React, { createContext, useContext, useCallback, useEffect, useState, useMemo } from 'react';
import { 
  VaultProvider, 
  useVault,
  useAuth as useVaultAuth,
  User,
  ApiError as VaultApiError 
} from '@vault/react';
import type { 
  VaultAuthProviderProps, 
  VaultAuthContextValue,
  LoginCredentials,
  SignupData,
  AuthError,
  Theme 
} from '../types';
import { getThemeClass, applyThemeVariables } from '../styles';

// ============================================================================
// Context
// ============================================================================

const VaultAuthContext = createContext<VaultAuthContextValue | null>(null);

// ============================================================================
// Internal Provider Component
// ============================================================================

interface InternalProviderProps {
  children: React.ReactNode;
  onAuthChange?: (user: User | null) => void;
  defaultTheme?: Theme;
  themeVariables?: Record<string, string>;
  apiKey: string;
  baseUrl: string;
}

function VaultAuthInternalProvider({ 
  children, 
  onAuthChange,
  defaultTheme = 'light',
  themeVariables,
}: InternalProviderProps) {
  const vault = useVault();
  const vaultAuth = useVaultAuth();
  const [error, setError] = useState<AuthError | null>(null);
  const [theme, setThemeState] = useState<Theme>(defaultTheme);

  // Apply theme variables on mount
  useEffect(() => {
    if (themeVariables) {
      const container = document.querySelector('.vault-ui');
      if (container instanceof HTMLElement) {
        applyThemeVariables(container, themeVariables);
      }
    }
  }, [themeVariables]);

  // Notify auth changes
  useEffect(() => {
    onAuthChange?.(vaultAuth.user);
  }, [vaultAuth.user, onAuthChange]);

  const setTheme = useCallback((newTheme: Theme) => {
    setThemeState(newTheme);
  }, []);

  const clearError = useCallback(() => {
    setError(null);
  }, []);

  const convertError = useCallback((err: unknown): AuthError => {
    if (err && typeof err === 'object') {
      const apiError = err as VaultApiError;
      return {
        code: apiError.code || 'unknown_error',
        message: apiError.message || 'An unexpected error occurred',
      };
    }
    return {
      code: 'unknown_error',
      message: err instanceof Error ? err.message : 'An unexpected error occurred',
    };
  }, []);

  const login = useCallback(async (credentials: LoginCredentials) => {
    try {
      setError(null);
      await vaultAuth.signIn({
        email: credentials.email,
        password: credentials.password,
      });
    } catch (err) {
      const authError = convertError(err);
      setError(authError);
      throw authError;
    }
  }, [vaultAuth, convertError]);

  const logout = useCallback(async () => {
    try {
      setError(null);
      await vaultAuth.signOut();
    } catch (err) {
      const authError = convertError(err);
      setError(authError);
      throw authError;
    }
  }, [vaultAuth, convertError]);

  const signup = useCallback(async (data: SignupData) => {
    try {
      setError(null);
      await vaultAuth.signUp({
        email: data.email,
        password: data.password,
        name: data.name,
        givenName: data.name?.split(' ')[0],
        familyName: data.name?.split(' ').slice(1).join(' '),
      });
    } catch (err) {
      const authError = convertError(err);
      setError(authError);
      throw authError;
    }
  }, [vaultAuth, convertError]);

  const resetPassword = useCallback(async (email: string) => {
    try {
      setError(null);
      await vault.sendForgotPassword({ email });
    } catch (err) {
      const authError = convertError(err);
      setError(authError);
      throw authError;
    }
  }, [vault, convertError]);

  const completePasswordReset = useCallback(async (token: string, newPassword: string) => {
    try {
      setError(null);
      await vault.resetPassword({ token, password: newPassword });
    } catch (err) {
      const authError = convertError(err);
      setError(authError);
      throw authError;
    }
  }, [vault, convertError]);

  const value = useMemo<VaultAuthContextValue>(() => ({
    user: vaultAuth.user,
    isLoading: !vaultAuth.isLoaded,
    isAuthenticated: vaultAuth.isSignedIn,
    login,
    logout,
    signup,
    resetPassword,
    completePasswordReset,
    error,
    clearError,
    config: {
      apiKey: '', // Set by VaultProvider
      baseUrl: '', // Set by VaultProvider
    },
    theme,
    setTheme,
  }), [
    vaultAuth.user,
    vaultAuth.isLoaded,
    vaultAuth.isSignedIn,
    login,
    logout,
    signup,
    resetPassword,
    completePasswordReset,
    error,
    clearError,
    theme,
    setTheme,
  ]);

  return (
    <VaultAuthContext.Provider value={value}>
      {children}
    </VaultAuthContext.Provider>
  );
}

// ============================================================================
// Public Provider Component
// ============================================================================

export function VaultAuthProvider({
  apiKey,
  baseUrl,
  children,
  onAuthChange,
  defaultTheme = 'light',
  themeVariables,
}: VaultAuthProviderProps) {
  const config = useMemo(() => ({
    apiUrl: baseUrl,
    tenantId: apiKey,
  }), [apiKey, baseUrl]);

  return (
    <VaultProvider config={config}>
      <VaultAuthInternalProvider
        apiKey={apiKey}
        baseUrl={baseUrl}
        onAuthChange={onAuthChange}
        defaultTheme={defaultTheme}
        themeVariables={themeVariables}
      >
        <div className={`vault-ui ${getThemeClass(defaultTheme)}`} data-vault-theme={defaultTheme}>
          {children}
        </div>
      </VaultAuthInternalProvider>
    </VaultProvider>
  );
}

// ============================================================================
// Hook
// ============================================================================

export function useVaultAuthContext(): VaultAuthContextValue {
  const context = useContext(VaultAuthContext);
  
  if (!context) {
    throw new Error('useVaultAuthContext must be used within a VaultAuthProvider');
  }
  
  return context;
}

export { VaultAuthContext };
