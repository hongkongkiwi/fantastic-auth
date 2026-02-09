/**
 * useAuth Hook
 * 
 * Primary hook for authentication in the Vault React UI library.
 * Provides a simplified interface over the core SDK.
 */

import { useCallback, useMemo } from 'react';
import { useVaultAuthContext } from '../context/VaultAuthContext';
import type { UseAuthReturn, LoginCredentials, SignupData } from '../types';

/**
 * Hook to access authentication state and methods.
 * Must be used within a VaultAuthProvider.
 * 
 * @returns Authentication state and methods
 * 
 * @example
 * ```tsx
 * function App() {
 *   const { isAuthenticated, user, login, logout } = useAuth();
 *   
 *   if (!isAuthenticated) {
 *     return <LoginForm onSuccess={() => console.log('Logged in!')} />;
 *   }
 *   
 *   return (
 *     <div>
 *       <p>Welcome, {user?.email}</p>
 *       <button onClick={logout}>Sign out</button>
 *     </div>
 *   );
 * }
 * ```
 */
export function useAuth(): UseAuthReturn {
  const context = useVaultAuthContext();

  return useMemo(() => ({
    user: context.user,
    isLoading: context.isLoading,
    isAuthenticated: context.isAuthenticated,
    login: context.login,
    logout: context.logout,
    signup: context.signup,
    resetPassword: context.resetPassword,
    completePasswordReset: context.completePasswordReset,
    error: context.error,
    clearError: context.clearError,
  }), [
    context.user,
    context.isLoading,
    context.isAuthenticated,
    context.login,
    context.logout,
    context.signup,
    context.resetPassword,
    context.completePasswordReset,
    context.error,
    context.clearError,
  ]);
}

/**
 * Hook to check if user is currently loading
 * 
 * @returns Boolean indicating if auth state is loading
 */
export function useIsAuthLoading(): boolean {
  const { isLoading } = useVaultAuthContext();
  return isLoading;
}

/**
 * Hook to check if user is authenticated
 * 
 * @returns Boolean indicating if user is authenticated
 */
export function useIsAuthenticated(): boolean {
  const { isAuthenticated } = useVaultAuthContext();
  return isAuthenticated;
}

/**
 * Hook to get the current user
 * 
 * @returns Current user or null
 */
export function useCurrentUser() {
  const { user, isLoading } = useVaultAuthContext();
  return { user, isLoading };
}

/**
 * Hook for login functionality
 * 
 * @returns Login function and loading state
 */
export function useLogin() {
  const { login, isLoading, error, clearError } = useVaultAuthContext();
  
  return useMemo(() => ({
    login,
    isLoading,
    error,
    clearError,
  }), [login, isLoading, error, clearError]);
}

/**
 * Hook for signup functionality
 * 
 * @returns Signup function and loading state
 */
export function useSignup() {
  const { signup, isLoading, error, clearError } = useVaultAuthContext();
  
  return useMemo(() => ({
    signup,
    isLoading,
    error,
    clearError,
  }), [signup, isLoading, error, clearError]);
}

/**
 * Hook for logout functionality
 * 
 * @returns Logout function
 */
export function useLogout() {
  const { logout } = useVaultAuthContext();
  return logout;
}

/**
 * Hook for password reset functionality
 * 
 * @returns Password reset functions and loading state
 */
export function usePasswordReset() {
  const { resetPassword, completePasswordReset, isLoading, error, clearError } = useVaultAuthContext();
  
  return useMemo(() => ({
    sendResetEmail: resetPassword,
    resetPassword: completePasswordReset,
    isLoading,
    error,
    clearError,
  }), [resetPassword, completePasswordReset, isLoading, error, clearError]);
}
