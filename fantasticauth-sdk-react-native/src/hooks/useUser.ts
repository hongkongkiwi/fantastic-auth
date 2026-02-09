/**
 * useUser Hook
 * 
 * Hook for user data and management in React Native.
 * 
 * @example
 * ```tsx
 * function Profile() {
 *   const { user, isLoaded, update, reload } = useUserManager();
 *   
 *   if (!isLoaded) {
 *     return <Loading />;
 *   }
 *   
 *   if (!user) {
 *     return <SignInPrompt />;
 *   }
 *   
 *   return (
 *     <View>
 *       <Text>{user.email}</Text>
 *       <Text>{user.profile.name}</Text>
 *       <Button onPress={() => reload()}>
 *         Refresh
 *       </Button>
 *     </View>
 *   );
 * }
 * ```
 */

import { useCallback, useState } from 'react';
import { useVault } from '../VaultProvider';
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
 * Complete hook for user data and management.
 * 
 * @returns User data and management functions
 */
export function useUserManager(): UseUserReturn & {
  isLoading: boolean;
  error: ApiError | null;
  changePassword: (currentPassword: string, newPassword: string) => Promise<void>;
  deleteUser: () => Promise<void>;
  uploadAvatar: (uri: string) => Promise<string>;
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

  const uploadAvatar = useCallback(async (uri: string): Promise<string> => {
    setIsLoading(true);
    setError(null);
    try {
      // Create form data for file upload
      const formData = new FormData();
      const filename = uri.split('/').pop() || 'avatar.jpg';
      const match = /\.([^.]+)$/.exec(filename);
      const type = match ? `image/${match[1]}` : 'image/jpeg';
      
      // @ts-ignore - React Native FormData accepts files
      formData.append('avatar', {
        uri,
        name: filename,
        type,
      });

      const baseUrl = vault.config.apiUrl.replace(/\/$/, '');
      const token = await vault.getToken();
      
      const response = await fetch(`${baseUrl}/api/v1/users/me/avatar`, {
        method: 'POST',
        headers: {
          'X-Tenant-ID': vault.config.tenantId,
          ...(token && { Authorization: `Bearer ${token}` }),
        },
        body: formData,
      });

      if (!response.ok) {
        const error = await response.json().catch(() => ({
          message: 'Failed to upload avatar',
          code: 'avatar_upload_error',
        }));
        throw error;
      }

      const result = await response.json();
      return result.url;
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
    uploadAvatar,
  };
}
