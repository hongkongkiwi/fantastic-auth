/**
 * useUser Hook
 * 
 * Hook for user data and management.
 * 
 * @example
 * ```tsx
 * function Profile() {
 *   const user = useUser();
 *   const { updateUser, reloadUser } = useUpdateUser();
 *   
 *   if (!user) return null;
 *   
 *   return <div>Hello {user.email}</div>;
 * }
 * ```
 */

import { useCallback, useState } from 'react';
import { useVault } from '../context/VaultContext';
import { User, UserProfile, UseUserReturn, ApiError } from '../types';

/**
 * Hook to get the current user.
 * Returns null if not signed in.
 * 
 * @returns The current user or null
 */
export function useUser(): User | null {
  const vault = useVault();
  return vault.user;
}

/**
 * Hook for user management operations.
 * 
 * @returns Object with update and reload functions
 */
export function useUpdateUser(): {
  updateUser: (updates: Partial<User>) => Promise<void>;
  reloadUser: () => Promise<void>;
  isLoading: boolean;
  error: ApiError | null;
} {
  const vault = useVault();
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);

  const updateUser = useCallback(async (updates: Partial<User>) => {
    setIsLoading(true);
    setError(null);
    try {
      await vault.updateUser(updates);
    } catch (err) {
      setError(err as ApiError);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [vault]);

  const reloadUser = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      await vault.reloadUser();
    } catch (err) {
      setError(err as ApiError);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [vault]);

  return {
    updateUser,
    reloadUser,
    isLoading,
    error,
  };
}

/**
 * Complete hook for user data and management.
 * 
 * @returns User data and management functions
 */
export function useUserManager(): UseUserReturn & {
  isLoading: boolean;
  error: ApiError | null;
  changePassword: (currentPassword: string, newPassword: string) => Promise<void>;
  deleteUser: () => Promise<void>;
} {
  const vault = useVault();
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);

  const update = useCallback(async (updates: Partial<User>) => {
    setIsLoading(true);
    setError(null);
    try {
      await vault.updateUser(updates);
    } catch (err) {
      setError(err as ApiError);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [vault]);

  const reload = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      await vault.reloadUser();
    } catch (err) {
      setError(err as ApiError);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [vault]);

  const changePassword = useCallback(async (currentPassword: string, newPassword: string) => {
    setIsLoading(true);
    setError(null);
    try {
      await vault.changePassword(currentPassword, newPassword);
    } catch (err) {
      setError(err as ApiError);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [vault]);

  const deleteUser = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      await vault.deleteUser();
    } catch (err) {
      setError(err as ApiError);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [vault]);

  return {
    user: vault.user,
    isLoaded: vault.isLoaded,
    isLoading,
    error,
    update,
    reload,
    changePassword,
    deleteUser,
  };
}
