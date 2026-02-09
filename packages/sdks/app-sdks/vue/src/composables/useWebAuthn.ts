/**
 * useWebAuthn Composable
 *
 * Composable for WebAuthn/Passkey authentication.
 *
 * @example
 * ```vue
 * <script setup lang="ts">
 * import { useWebAuthn } from '@fantasticauth/vue';
 *
 * const { isSupported, register, authenticate, isLoading } = useWebAuthn();
 * </script>
 *
 * <template>
 *   <div v-if="!isSupported">
 *     <p>Passkeys not supported on this device</p>
 *   </div>
 *   <div v-else>
 *     <button @click="register()" :disabled="isLoading">
 *       Register Passkey
 *     </button>
 *     <button @click="authenticate()" :disabled="isLoading">
 *       Sign in with Passkey
 *     </button>
 *   </div>
 * </template>
 * ```
 */

import { ref, onMounted } from 'vue';
import type { Ref } from 'vue';
import type { UseWebAuthnReturn, ApiError, Session } from '../types';
import { useVault } from '../plugin';

// ============================================================================
// WebAuthn Utilities
// ============================================================================

/**
 * Encode ArrayBuffer to base64url string
 */
function bufferToBase64url(buffer: ArrayBuffer): string {
  const base64 = btoa(String.fromCharCode(...new Uint8Array(buffer)));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Decode base64url string to ArrayBuffer
 */
function base64urlToBuffer(base64url: string): ArrayBuffer {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(base64);
  const buffer = new ArrayBuffer(binary.length);
  const view = new Uint8Array(buffer);
  for (let i = 0; i < binary.length; i++) {
    view[i] = binary.charCodeAt(i);
  }
  return buffer;
}

// ============================================================================
// Composable
// ============================================================================

/**
 * Composable for WebAuthn/Passkey operations.
 *
 * @returns WebAuthn methods and state
 */
export function useWebAuthn(): UseWebAuthnReturn {
  const vault = useVault();
  const isSupported = ref(false);
  const isLoading = ref(false);
  const error = ref<ApiError | null>(null);

  // Check WebAuthn support on mount
  onMounted(() => {
    const checkSupport = () => {
      if (typeof window === 'undefined') {
        isSupported.value = false;
        return;
      }

      const supported =
        typeof window.PublicKeyCredential !== 'undefined' &&
        typeof window.navigator?.credentials?.create === 'function';

      isSupported.value = supported;
    };

    checkSupport();
  });

  const resetError = () => {
    error.value = null;
  };

  /**
   * Register a new WebAuthn credential (passkey)
   */
  const register = async (name?: string) => {
    if (!isSupported.value) {
      throw new Error('WebAuthn is not supported on this device');
    }

    isLoading.value = true;
    error.value = null;

    try {
      // Get registration options from server
      const options = await fetch('/api/v1/webauthn/register/begin', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
      }).then(r => r.json());

      // Create credential
      const credential = await navigator.credentials.create({
        publicKey: {
          ...options,
          challenge: base64urlToBuffer(options.challenge),
          user: {
            ...options.user,
            id: base64urlToBuffer(options.user.id),
          },
        },
      }) as PublicKeyCredential;

      if (!credential) {
        throw new Error('Failed to create credential');
      }

      const response = credential.response as AuthenticatorAttestationResponse;

      // Send credential to server
      await fetch('/api/v1/webauthn/register/finish', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          credential: {
            id: credential.id,
            rawId: bufferToBase64url(credential.rawId),
            type: credential.type,
            response: {
              clientDataJSON: bufferToBase64url(response.clientDataJSON),
              attestationObject: bufferToBase64url(response.attestationObject),
            },
          },
          name,
        }),
      });
    } catch (err: any) {
      const apiError: ApiError = {
        code: err.name === 'NotAllowedError' ? 'user_cancelled' : 'webauthn_error',
        message: err.message || 'WebAuthn operation failed',
      };
      error.value = apiError;
      throw apiError;
    } finally {
      isLoading.value = false;
    }
  };

  /**
   * Authenticate using WebAuthn
   */
  const authenticate = async (): Promise<Session | null> => {
    if (!isSupported.value) {
      throw new Error('WebAuthn is not supported on this device');
    }

    isLoading.value = true;
    error.value = null;

    try {
      // Get authentication options from server
      const options = await fetch('/api/v1/webauthn/authenticate/begin', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
      }).then(r => r.json());

      // Get credential
      const credential = await navigator.credentials.get({
        publicKey: {
          ...options,
          challenge: base64urlToBuffer(options.challenge),
          allowCredentials: options.allowCredentials?.map((cred: any) => ({
            ...cred,
            id: base64urlToBuffer(cred.id),
          })),
        },
      }) as PublicKeyCredential;

      if (!credential) {
        throw new Error('Failed to get credential');
      }

      const response = credential.response as AuthenticatorAssertionResponse;

      // Send credential to server
      const result = await fetch('/api/v1/webauthn/authenticate/finish', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          credential: {
            id: credential.id,
            rawId: bufferToBase64url(credential.rawId),
            type: credential.type,
            response: {
              clientDataJSON: bufferToBase64url(response.clientDataJSON),
              authenticatorData: bufferToBase64url(response.authenticatorData),
              signature: bufferToBase64url(response.signature),
              userHandle: response.userHandle ? bufferToBase64url(response.userHandle) : null,
            },
          },
        }),
      }).then(r => r.json());

      // Store session
      if (result.session) {
        await vault.setSessionTokens(result.session);
      }

      return result.session || null;
    } catch (err: any) {
      const apiError: ApiError = {
        code: err.name === 'NotAllowedError' ? 'user_cancelled' : 'webauthn_error',
        message: err.message || 'WebAuthn authentication failed',
      };
      error.value = apiError;
      throw apiError;
    } finally {
      isLoading.value = false;
    }
  };

  return {
    isSupported,
    isLoading,
    error,
    register,
    authenticate,
    resetError,
  };
}

/**
 * Composable to check if WebAuthn is supported on the current device.
 *
 * @returns Boolean ref indicating WebAuthn support
 */
export function useIsWebAuthnSupported(): Ref<boolean> {
  const isSupported = ref(false);

  onMounted(() => {
    if (typeof window === 'undefined') {
      isSupported.value = false;
      return;
    }

    const supported =
      typeof window.PublicKeyCredential !== 'undefined' &&
      typeof window.navigator?.credentials?.create === 'function';

    isSupported.value = supported;
  });

  return isSupported;
}
