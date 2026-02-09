/**
 * User Stores
 * 
 * Svelte stores and runes for user management.
 */

import { getVaultContext } from '../context.js';
import type { User, ApiError } from '../types.js';

/**
 * useUser - Svelte 5 rune for user state and operations
 * 
 * @example
 * ```svelte
 * <script>
 *   import { useUser } from '@fantasticauth/svelte';
 *   const { user, update, reload } = useUser();
 * </script>
 * 
 * {#if user}
 *   <p>{user.email}</p>
 *   <button onclick={() => update({ name: 'New Name' })}>
 *     Update Name
 *   </button>
 * {/if}
 * ```
 */
export function useUser() {
  const vault = getVaultContext();
  
  let isLoading = $state(false);
  let error = $state<ApiError | null>(null);
  
  async function update(updates: Partial<User>): Promise<void> {
    isLoading = true;
    error = null;
    try {
      await vault.updateUser(updates);
    } catch (e) {
      error = e as ApiError;
      throw e;
    } finally {
      isLoading = false;
    }
  }
  
  async function reload(): Promise<void> {
    isLoading = true;
    error = null;
    try {
      await vault.reloadUser();
    } catch (e) {
      error = e as ApiError;
      throw e;
    } finally {
      isLoading = false;
    }
  }
  
  async function changePassword(currentPassword: string, newPassword: string): Promise<void> {
    isLoading = true;
    error = null;
    try {
      await vault.changePassword(currentPassword, newPassword);
    } catch (e) {
      error = e as ApiError;
      throw e;
    } finally {
      isLoading = false;
    }
  }
  
  async function deleteAccount(): Promise<void> {
    isLoading = true;
    error = null;
    try {
      await vault.deleteUser();
    } catch (e) {
      error = e as ApiError;
      throw e;
    } finally {
      isLoading = false;
    }
  }
  
  return {
    get user() {
      let value = $state<User | null>(null);
      vault.user.subscribe(v => value = v)();
      return value;
    },
    get isLoaded() {
      let value = $state(false);
      vault.isLoaded.subscribe(v => value = v)();
      return value;
    },
    get isLoading() { return isLoading; },
    get error() { return error; },
    update,
    reload,
    changePassword,
    deleteAccount,
  };
}

/**
 * useUpdateUser - Hook specifically for updating user data
 * 
 * @example
 * ```svelte
 * <script>
 *   import { useUpdateUser } from '@fantasticauth/svelte';
 *   const { update, isLoading } = useUpdateUser();
 * </script>
 * ```
 */
export function useUpdateUser() {
  const vault = getVaultContext();
  
  let isLoading = $state(false);
  let error = $state<ApiError | null>(null);
  
  async function update(updates: Partial<User>): Promise<void> {
    isLoading = true;
    error = null;
    try {
      await vault.updateUser(updates);
    } catch (e) {
      error = e as ApiError;
      throw e;
    } finally {
      isLoading = false;
    }
  }
  
  return {
    get isLoading() { return isLoading; },
    get error() { return error; },
    update,
  };
}
