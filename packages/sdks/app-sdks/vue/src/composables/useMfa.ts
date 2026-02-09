/**
 * useMfa Composable
 *
 * Composable for Multi-Factor Authentication management.
 *
 * @example
 * ```vue
 * <script setup lang="ts">
 * import { useMfa } from '@vault/vue';
 *
 * const { setupTotp, verifyTotp, isLoading, error } = useMfa();
 *
 * const handleSetup = async () => {
 *   const setup = await setupTotp();
 *   // Display QR code from setup.qrCode
 * };
 * </script>
 * ```
 */

import { ref } from 'vue';
import type { Ref } from 'vue';
import { useVault } from '../plugin';
import type { UseMfaReturn, MfaMethod, TotpSetup, ApiError } from '../types';

/**
 * Composable for MFA operations.
 *
 * @returns MFA methods and state
 */
export function useMfa(): UseMfaReturn {
  const vault = useVault();
  const isLoading = ref(false);
  const error = ref<ApiError | null>(null);

  const resetError = () => {
    error.value = null;
  };

  const setupTotp = async (): Promise<TotpSetup | null> => {
    isLoading.value = true;
    error.value = null;
    try {
      return await vault.setupTotp();
    } catch (err) {
      error.value = err as ApiError;
      throw err;
    } finally {
      isLoading.value = false;
    }
  };

  const verifyTotp = async (code: string) => {
    isLoading.value = true;
    error.value = null;
    try {
      await vault.verifyTotpSetup(code);
    } catch (err) {
      error.value = err as ApiError;
      throw err;
    } finally {
      isLoading.value = false;
    }
  };

  const enableMfa = async (method: MfaMethod) => {
    isLoading.value = true;
    error.value = null;
    try {
      // This would call the API to enable MFA
      // await vault.enableMfa(method);
    } catch (err) {
      error.value = err as ApiError;
      throw err;
    } finally {
      isLoading.value = false;
    }
  };

  const disableMfa = async (method: MfaMethod) => {
    isLoading.value = true;
    error.value = null;
    try {
      await vault.disableMfa(method);
    } catch (err) {
      error.value = err as ApiError;
      throw err;
    } finally {
      isLoading.value = false;
    }
  };

  const generateBackupCodes = async (): Promise<string[]> => {
    isLoading.value = true;
    error.value = null;
    try {
      return await vault.generateBackupCodes();
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
    setupTotp,
    verifyTotp,
    enableMfa,
    disableMfa,
    generateBackupCodes,
    resetError,
  };
}

/**
 * Composable to check if MFA is enabled for the current user.
 *
 * @returns Boolean ref indicating if MFA is enabled
 */
export function useIsMfaEnabled(): Ref<boolean> {
  const vault = useVault();
  return ref(vault.user.value?.mfaEnabled || false);
}

/**
 * Composable to get MFA methods for the current user.
 *
 * @returns Array ref of MFA methods
 */
export function useMfaMethods(): Ref<string[]> {
  const vault = useVault();
  return ref(vault.user.value?.mfaMethods || []);
}
