/**
 * useWebAuthn Hook
 * 
 * Hook for WebAuthn/Passkey authentication.
 * 
 * @example
 * ```tsx
 * function PasskeyButton() {
 *   const { isSupported, register, authenticate, isLoading } = useWebAuthn();
 *   
 *   if (!isSupported) {
 *     return <p>Passkeys not supported on this device</p>;
 *   }
 *   
 *   return (
 *     <>
 *       <button onClick={() => register()} disabled={isLoading}>
 *         Register Passkey
 *       </button>
 *       <button onClick={() => authenticate()} disabled={isLoading}>
 *         Sign in with Passkey
 *       </button>
 *     </>
 *   );
 * }
 * ```
 */

import { useCallback, useEffect, useState } from 'react';
import { useVault } from '../context/VaultContext';
import { VaultApiClient } from '../api/client';
import { UseWebAuthnReturn, ApiError, Session } from '../types';

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

/**
 * Hook for WebAuthn/Passkey operations.
 * 
 * @returns WebAuthn methods and state
 */
export function useWebAuthn(): UseWebAuthnReturn {
  const vault = useVault();
  const [isSupported, setIsSupported] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);

  // Check WebAuthn support on mount
  useEffect(() => {
    const checkSupport = () => {
      if (typeof window === 'undefined') {
        setIsSupported(false);
        return;
      }
      
      const supported = 
        typeof window.PublicKeyCredential !== 'undefined' &&
        typeof window.navigator?.credentials?.create === 'function';
      
      setIsSupported(supported);
    };

    checkSupport();
  }, []);

  const resetError = useCallback(() => {
    setError(null);
  }, []);

  /**
   * Register a new WebAuthn credential (passkey)
   */
  const register = useCallback(async (name?: string) => {
    if (!isSupported) {
      throw new Error('WebAuthn is not supported on this device');
    }

    setIsLoading(true);
    setError(null);

    try {
      // Get registration options from server
      const api = new VaultApiClient({
        apiUrl: '', // Will be set from context
        tenantId: '', // Will be set from context
      });
      
      // We need to access the API client from the vault context
      // For now, we'll use a workaround
      const options = await (vault as any).api?.beginWebAuthnRegistration?.() || 
        await fetch('/api/v1/webauthn/register/begin', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${await vault.getToken()}`,
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
          'Authorization': `Bearer ${await vault.getToken()}`,
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

      // Reload user to get updated MFA methods
      await vault.reloadUser();
    } catch (err: any) {
      const apiError: ApiError = {
        code: err.name === 'NotAllowedError' ? 'user_cancelled' : 'webauthn_error',
        message: err.message || 'WebAuthn operation failed',
      };
      setError(apiError);
      throw apiError;
    } finally {
      setIsLoading(false);
    }
  }, [isSupported, vault]);

  /**
   * Authenticate using WebAuthn
   */
  const authenticate = useCallback(async (): Promise<Session | null> => {
    if (!isSupported) {
      throw new Error('WebAuthn is not supported on this device');
    }

    setIsLoading(true);
    setError(null);

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
        localStorage.setItem('vault_session_token', result.session.accessToken);
        if (result.session.refreshToken) {
          localStorage.setItem('vault_refresh_token', result.session.refreshToken);
        }
      }

      return result.session || null;
    } catch (err: any) {
      const apiError: ApiError = {
        code: err.name === 'NotAllowedError' ? 'user_cancelled' : 'webauthn_error',
        message: err.message || 'WebAuthn authentication failed',
      };
      setError(apiError);
      throw apiError;
    } finally {
      setIsLoading(false);
    }
  }, [isSupported]);

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
 * Hook to check if WebAuthn is supported on the current device.
 * 
 * @returns Boolean indicating WebAuthn support
 */
export function useIsWebAuthnSupported(): boolean {
  const [isSupported, setIsSupported] = useState(false);

  useEffect(() => {
    if (typeof window === 'undefined') {
      setIsSupported(false);
      return;
    }

    const supported = 
      typeof window.PublicKeyCredential !== 'undefined' &&
      typeof window.navigator?.credentials?.create === 'function';

    setIsSupported(supported);
  }, []);

  return isSupported;
}
