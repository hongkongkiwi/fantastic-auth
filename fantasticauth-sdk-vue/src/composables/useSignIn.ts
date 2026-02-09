/**
 * useSignIn Composable
 *
 * Composable for sign-in functionality with loading and error states.
 *
 * @example
 * ```vue
 * <script setup lang="ts">
 * import { ref } from 'vue';
 * import { useSignIn } from '@vault/vue';
 *
 * const email = ref('');
 * const password = ref('');
 * const { signIn, isLoading, error, resetError } = useSignIn();
 *
 * const handleSubmit = async () => {
 *   try {
 *     await signIn({ email: email.value, password: password.value });
 *   } catch (err) {
 *     // Error is already available in `error` ref
 *   }
 * };
 * </script>
 *
 * <template>
 *   <form @submit.prevent="handleSubmit">
 *     <input v-model="email" type="email" />
 *     <input v-model="password" type="password" />
 *     <p v-if="error" class="error">{{ error.message }}</p>
 *     <button :disabled="isLoading">
 *       {{ isLoading ? 'Signing in...' : 'Sign In' }}
 *     </button>
 *   </form>
 * </template>
 * ```
 */

import { ref } from 'vue';
import type { Ref } from 'vue';
import { useVault } from '../plugin';
import type {
  SignInOptions,
  MagicLinkOptions,
  OAuthOptions,
  UseSignInReturn,
  ApiError,
} from '../types';

/**
 * Composable for sign-in operations.
 * Provides loading states and error handling.
 *
 * @returns Sign-in methods and state
 */
export function useSignIn(): UseSignInReturn {
  const vault = useVault();
  const isLoading = ref(false);
  const error = ref<ApiError | null>(null);

  const resetError = () => {
    error.value = null;
  };

  const signIn = async (options: SignInOptions) => {
    isLoading.value = true;
    error.value = null;
    try {
      await vault.signIn(options);
    } catch (err) {
      error.value = err as ApiError;
      throw err;
    } finally {
      isLoading.value = false;
    }
  };

  const signInWithMagicLink = async (options: MagicLinkOptions) => {
    isLoading.value = true;
    error.value = null;
    try {
      await vault.signInWithMagicLink(options);
    } catch (err) {
      error.value = err as ApiError;
      throw err;
    } finally {
      isLoading.value = false;
    }
  };

  const signInWithOAuth = async (options: OAuthOptions) => {
    isLoading.value = true;
    error.value = null;
    try {
      await vault.signInWithOAuth(options);
    } catch (err) {
      error.value = err as ApiError;
      throw err;
    } finally {
      isLoading.value = false;
    }
  };

  return {
    isLoading,
    error,
    signIn,
    signInWithMagicLink,
    signInWithOAuth,
    resetError,
  };
}
