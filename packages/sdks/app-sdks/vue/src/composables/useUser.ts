/**
 * useUser Composable
 *
 * Composable for user data and management.
 *
 * @example
 * ```vue
 * <script setup lang="ts">
 * import { useUser, useUpdateUser } from '@fantasticauth/vue';
 *
 * const user = useUser();
 * const { updateUser, reloadUser, isLoading } = useUpdateUser();
 * </script>
 *
 * <template>
 *   <div v-if="user">
 *     <p>Hello {{ user.email }}</p>
 *     <button @click="reloadUser" :disabled="isLoading">Reload</button>
 *   </div>
 * </template>
 * ```
 */

import { ref, computed } from 'vue';
import type { Ref } from 'vue';
import { useVault } from '../plugin';
import type { User, UserProfile, UseUserReturn, ApiError } from '../types';

/**
 * Composable to get the current user.
 * Returns null if not signed in.
 *
 * @returns The current user ref or null ref
 */
export function useUser(): Ref<User | null> {
  const vault = useVault();
  return vault.user;
}

/**
 * Composable for user management operations.
 *
 * @returns Object with update and reload functions
 */
export function useUpdateUser(): {
  updateUser: (updates: Partial<User>) => Promise<void>;
  reloadUser: () => Promise<void>;
  isLoading: Ref<boolean>;
  error: Ref<ApiError | null>;
} {
  const vault = useVault();
  const isLoading = ref(false);
  const error = ref<ApiError | null>(null);

  const updateUser = async (updates: Partial<User>) => {
    isLoading.value = true;
    error.value = null;
    try {
      await vault.updateUser(updates);
    } catch (err) {
      error.value = err as ApiError;
      throw err;
    } finally {
      isLoading.value = false;
    }
  };

  const reloadUser = async () => {
    isLoading.value = true;
    error.value = null;
    try {
      await vault.reloadUser();
    } catch (err) {
      error.value = err as ApiError;
      throw err;
    } finally {
      isLoading.value = false;
    }
  };

  return {
    updateUser,
    reloadUser,
    isLoading,
    error,
  };
}

/**
 * Complete composable for user data and management.
 *
 * @returns User data and management functions
 */
export function useUserManager(): UseUserReturn & {
  isLoading: Ref<boolean>;
  error: Ref<ApiError | null>;
  changePassword: (currentPassword: string, newPassword: string) => Promise<void>;
  deleteUser: () => Promise<void>;
} {
  const vault = useVault();
  const isLoading = ref(false);
  const error = ref<ApiError | null>(null);

  const update = async (updates: Partial<User>) => {
    isLoading.value = true;
    error.value = null;
    try {
      await vault.updateUser(updates);
    } catch (err) {
      error.value = err as ApiError;
      throw err;
    } finally {
      isLoading.value = false;
    }
  };

  const reload = async () => {
    isLoading.value = true;
    error.value = null;
    try {
      await vault.reloadUser();
    } catch (err) {
      error.value = err as ApiError;
      throw err;
    } finally {
      isLoading.value = false;
    }
  };

  const changePassword = async (currentPassword: string, newPassword: string) => {
    isLoading.value = true;
    error.value = null;
    try {
      await vault.changePassword(currentPassword, newPassword);
    } catch (err) {
      error.value = err as ApiError;
      throw err;
    } finally {
      isLoading.value = false;
    }
  };

  const deleteUser = async () => {
    isLoading.value = true;
    error.value = null;
    try {
      await vault.deleteUser();
    } catch (err) {
      error.value = err as ApiError;
      throw err;
    } finally {
      isLoading.value = false;
    }
  };

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
