/**
 * useUser Hook
 * 
 * Hook for user management operations.
 */

import { useCallback, useMemo, useState } from 'react';
import { useUser as useVaultUser, useVault } from '@fantasticauth/react';
import type { UseUserReturn, AuthError, User } from '../types';

/**
 * Hook for user profile management.
 * 
 * @returns User data and management functions
 * 
 * @example
 * ```tsx
 * function ProfilePage() {
 *   const { user, update, isLoading } = useUser();
 *   
 *   const handleUpdate = async (updates) => {
 *     await update(updates);
 *   };
 *   
 *   return <UserProfile onUpdate={handleUpdate} />;
 * }
 * ```
 */
export function useUser(): UseUserReturn {
  const vaultUser = useVaultUser();
  const vault = useVault();
  const [error, setError] = useState<AuthError | null>(null);

  const convertError = useCallback((err: unknown): AuthError => {
    if (err && typeof err === 'object') {
      const apiError = err as { code?: string; message?: string };
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

  const update = useCallback(async (updates: Partial<User>) => {
    try {
      setError(null);
      await vaultUser.update(updates);
    } catch (err) {
      const authError = convertError(err);
      setError(authError);
      throw authError;
    }
  }, [vaultUser, convertError]);

  const reload = useCallback(async () => {
    try {
      setError(null);
      await vaultUser.reload();
    } catch (err) {
      const authError = convertError(err);
      setError(authError);
      throw authError;
    }
  }, [vaultUser, convertError]);

  const changePassword = useCallback(async (currentPassword: string, newPassword: string) => {
    try {
      setError(null);
      await vault.changePassword(currentPassword, newPassword);
    } catch (err) {
      const authError = convertError(err);
      setError(authError);
      throw authError;
    }
  }, [vault, convertError]);

  const deleteAccount = useCallback(async () => {
    try {
      setError(null);
      await vault.deleteUser();
    } catch (err) {
      const authError = convertError(err);
      setError(authError);
      throw authError;
    }
  }, [vault, convertError]);

  return useMemo(() => ({
    user: vaultUser.user,
    isLoading: !vaultUser.isLoaded,
    update,
    reload,
    changePassword,
    deleteAccount,
    error,
  }), [
    vaultUser.user,
    vaultUser.isLoaded,
    update,
    reload,
    changePassword,
    deleteAccount,
    error,
  ]);
}

/**
 * Hook to get user profile data
 * 
 * @returns User profile and loading state
 */
export function useUserProfile() {
  const { user, isLoading, reload } = useUser();
  
  return useMemo(() => ({
    profile: user?.profile || null,
    email: user?.email || null,
    emailVerified: user?.emailVerified || false,
    mfaEnabled: user?.mfaEnabled || false,
    isLoading,
    reload,
  }), [user, isLoading, reload]);
}

/**
 * Hook to check if email is verified
 * 
 * @returns Boolean indicating if email is verified
 */
export function useIsEmailVerified(): boolean {
  const { user } = useUser();
  return user?.emailVerified || false;
}

/**
 * Hook to check if MFA is enabled
 * 
 * @returns Boolean indicating if MFA is enabled
 */
export function useIsMfaEnabled(): boolean {
  const { user } = useUser();
  return user?.mfaEnabled || false;
}
