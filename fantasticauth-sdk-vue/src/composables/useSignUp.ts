/**
 * useSignUp Composable
 *
 * Composable for sign-up functionality with loading and error states.
 *
 * @example
 * ```vue
 * <script setup lang="ts">
 * import { ref } from 'vue';
 * import { useSignUp } from '@vault/vue';
 *
 * const email = ref('');
 * const password = ref('');
 * const name = ref('');
 * const { signUp, isLoading, error } = useSignUp();
 *
 * const handleSubmit = async () => {
 *   try {
 *     await signUp({
 *       email: email.value,
 *       password: password.value,
 *       name: name.value,
 *     });
 *   } catch (err) {
 *     // Handle error
 *   }
 * };
 * </script>
 *
 * <template>
 *   <form @submit.prevent="handleSubmit">
 *     <input v-model="name" placeholder="Full Name" />
 *     <input v-model="email" type="email" />
 *     <input v-model="password" type="password" />
 *     <p v-if="error">{{ error.message }}</p>
 *     <button :disabled="isLoading">
 *       {{ isLoading ? 'Creating account...' : 'Sign Up' }}
 *     </button>
 *   </form>
 * </template>
 * ```
 */

import { ref } from 'vue';
import type { Ref } from 'vue';
import { useVault } from '../plugin';
import type {
  SignUpOptions,
  OAuthOptions,
  UseSignUpReturn,
  ApiError,
} from '../types';

/**
 * Composable for sign-up operations.
 * Provides loading states and error handling.
 *
 * @returns Sign-up methods and state
 */
export function useSignUp(): UseSignUpReturn {
  const vault = useVault();
  const isLoading = ref(false);
  const error = ref<ApiError | null>(null);

  const resetError = () => {
    error.value = null;
  };

  const signUp = async (options: SignUpOptions) => {
    isLoading.value = true;
    error.value = null;
    try {
      await vault.signUp(options);
    } catch (err) {
      error.value = err as ApiError;
      throw err;
    } finally {
      isLoading.value = false;
    }
  };

  const signUpWithOAuth = async (options: OAuthOptions) => {
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
    signUp,
    signUpWithOAuth,
    resetError,
  };
}
