/**
 * useWebAuthn Hook
 * 
 * Hook for WebAuthn/Passkey authentication in React Native.
 * Uses platform authenticators (Face ID, Touch ID, Fingerprint).
 * 
 * @example
 * ```tsx
 * function BiometricSetup() {
 *   const { isSupported, register, authenticate } = useWebAuthn();
 *   
 *   if (!isSupported) {
 *     return <Text>Biometric authentication not supported</Text>;
 *   }
 *   
 *   return (
 *     <View>
 *       <Button onPress={() => register('My Device')}>
 *         Register Passkey
 *       </Button>
 *       <Button onPress={authenticate}>
 *         Sign in with Passkey
 *       </Button>
 *     </View>
 *   );
 * }
 * ```
 */

import { useState, useCallback, useEffect } from 'react';
import { Platform } from 'react-native';
import { useVault } from '../VaultProvider';
import { UseWebAuthnReturn, ApiError, Session } from '../types';
import { authenticateWithBiometrics, getBiometricType } from '../biometric';

/**
 * Check if WebAuthn is supported on the device
 * On React Native, this checks for biometric authentication availability
 */
export function useIsWebAuthnSupported(): boolean {
  const [isSupported, setIsSupported] = useState(false);

  useEffect(() => {
    checkSupport();
  }, []);

  const checkSupport = async () => {
    try {
      const type = await getBiometricType();
      setIsSupported(type !== 'none');
    } catch {
      setIsSupported(false);
    }
  };

  return isSupported;
}

/**
 * Hook for WebAuthn/Passkey operations.
 * 
 * @returns WebAuthn methods and state
 */
export function useWebAuthn(): UseWebAuthnReturn {
  const vault = useVault();
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [isSupported, setIsSupported] = useState(false);

  useEffect(() => {
    checkSupport();
  }, []);

  const checkSupport = async () => {
    try {
      const type = await getBiometricType();
      setIsSupported(type !== 'none');
    } catch {
      setIsSupported(false);
    }
  };

  const resetError = useCallback(() => {
    setError(null);
  }, []);

  const register = useCallback(async (name?: string): Promise<void> => {
    if (!isSupported) {
      throw { message: 'WebAuthn not supported', code: 'webauthn_not_supported' } as ApiError;
    }

    setIsLoading(true);
    setError(null);

    try {
      // First, authenticate with biometrics to verify user presence
      const authResult = await authenticateWithBiometrics('Register passkey');
      if (!authResult.success) {
        throw { 
          message: authResult.error || 'Biometric authentication failed', 
          code: 'biometric_failed' 
        } as ApiError;
      }

      // Begin registration with server
      const options = await vault.api.beginWebAuthnRegistration();

      // Create credential (in React Native, we use platform authenticator)
      // This is a simplified flow - actual implementation would use
      // a native module for WebAuthn credential creation
      
      // For now, we simulate by registering biometric credential
      await vault.api.finishWebAuthnRegistration({
        id: `${vault.user?.id}-${Date.now()}`,
        rawId: new Uint8Array(16),
        response: {},
        type: 'public-key',
      });

      // Refresh user data to get updated WebAuthn credentials
      await vault.reloadUser();
    } catch (err) {
      setError(err as ApiError);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [isSupported, vault]);

  const authenticate = useCallback(async (): Promise<Session | null> => {
    if (!isSupported) {
      throw { message: 'WebAuthn not supported', code: 'webauthn_not_supported' } as ApiError;
    }

    setIsLoading(true);
    setError(null);

    try {
      // Authenticate with biometrics
      const authResult = await authenticateWithBiometrics('Sign in with passkey');
      if (!authResult.success) {
        throw { 
          message: authResult.error || 'Biometric authentication failed', 
          code: 'biometric_failed' 
        } as ApiError;
      }

      // Begin authentication with server
      const options = await vault.api.beginWebAuthnAuthentication();

      // Get assertion (simplified - actual implementation would use native module)
      const credential = {
        id: 'credential-id',
        rawId: new Uint8Array(16),
        response: {},
        type: 'public-key',
      };

      // Finish authentication
      const result = await vault.api.finishWebAuthnAuthentication(credential);
      
      // Store session
      await vault.api.storeToken(result.session.accessToken);
      if (result.session.refreshToken) {
        await vault.api.storeRefreshToken(result.session.refreshToken);
      }

      // Update auth state
      await vault.reloadUser();

      return result.session;
    } catch (err) {
      setError(err as ApiError);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [isSupported, vault]);

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
 * Hook for managing WebAuthn credentials.
 * 
 * @example
 * ```tsx
 * function CredentialsManager() {
 *   const { credentials, isLoading, deleteCredential } = useWebAuthnCredentials();
 *   
 *   return (
 *     <View>
 *       {credentials.map(cred => (
 *         <CredentialItem 
 *           key={cred.id}
 *           credential={cred}
 *           onDelete={() => deleteCredential(cred.id)}
 *         />
 *       ))}
 *     </View>
 *   );
 * }
 * ```
 */
export function useWebAuthnCredentials(): {
  credentials: Array<{
    id: string;
    name: string;
    createdAt: string;
    lastUsedAt?: string;
  }>;
  isLoading: boolean;
  error: ApiError | null;
  deleteCredential: (credentialId: string) => Promise<void>;
  refresh: () => Promise<void>;
} {
  const vault = useVault();
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [credentials, setCredentials] = useState<Array<{
    id: string;
    name: string;
    createdAt: string;
    lastUsedAt?: string;
  }>>([]);

  const refresh = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const list = await vault.api.listWebAuthnCredentials();
      setCredentials(list);
    } catch (err) {
      setError(err as ApiError);
    } finally {
      setIsLoading(false);
    }
  }, [vault]);

  const deleteCredential = useCallback(async (credentialId: string) => {
    setIsLoading(true);
    setError(null);
    try {
      await vault.api.deleteWebAuthnCredential(credentialId);
      setCredentials(prev => prev.filter(c => c.id !== credentialId));
    } catch (err) {
      setError(err as ApiError);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [vault]);

  // Load credentials on mount
  useEffect(() => {
    if (vault.isSignedIn) {
      refresh();
    }
  }, [vault.isSignedIn]);

  return {
    credentials,
    isLoading,
    error,
    deleteCredential,
    refresh,
  };
}
