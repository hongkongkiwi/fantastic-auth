/**
 * useMfa Hook
 * 
 * Hook for Multi-Factor Authentication management.
 * 
 * @example
 * ```tsx
 * function MfaSetup() {
 *   const { setupTotp, verifyTotp, isLoading, error } = useMfa();
 *   const [qrCode, setQrCode] = useState<string | null>(null);
 *   
 *   const handleSetup = async () => {
 *     const setup = await setupTotp();
 *     setQrCode(setup.qrCode);
 *   };
 *   
 *   const handleVerify = async (code: string) => {
 *     await verifyTotp(code);
 *   };
 *   
 *   return (
 *     <div>
 *       {qrCode && <img src={qrCode} alt="Scan with authenticator app" />}
 *       <button onClick={handleSetup} disabled={isLoading}>
 *         Setup TOTP
 *       </button>
 *     </div>
 *   );
 * }
 * ```
 */

import { useCallback, useState } from 'react';
import { useVault } from '../context/VaultContext';
import { UseMfaReturn, MfaMethod, TotpSetup, ApiError } from '../types';

/**
 * Hook for MFA operations.
 * Provides methods to setup, verify, and manage MFA methods.
 * 
 * @returns MFA methods and state
 */
export function useMfa(): UseMfaReturn {
  const vault = useVault();
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);

  const resetError = useCallback(() => {
    setError(null);
  }, []);

  const setupTotp = useCallback(async (): Promise<TotpSetup | null> => {
    setIsLoading(true);
    setError(null);
    try {
      const setup = await vault.setupTotp();
      return setup;
    } catch (err) {
      setError(err as ApiError);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [vault]);

  const verifyTotp = useCallback(async (code: string) => {
    setIsLoading(true);
    setError(null);
    try {
      await vault.verifyTotpSetup(code);
    } catch (err) {
      setError(err as ApiError);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [vault]);

  const enableMfa = useCallback(async (method: MfaMethod) => {
    setIsLoading(true);
    setError(null);
    try {
      // This would call the API to enable MFA
      // For TOTP, setupTotp should be called first
      if (method === 'totp') {
        await vault.setupTotp();
      }
      await vault.reloadUser();
    } catch (err) {
      setError(err as ApiError);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [vault]);

  const disableMfa = useCallback(async (method: MfaMethod) => {
    setIsLoading(true);
    setError(null);
    try {
      await vault.disableMfa(method);
    } catch (err) {
      setError(err as ApiError);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [vault]);

  const generateBackupCodes = useCallback(async (): Promise<string[]> => {
    setIsLoading(true);
    setError(null);
    try {
      const codes = await vault.generateBackupCodes();
      return codes;
    } catch (err) {
      setError(err as ApiError);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [vault]);

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
 * Hook to verify MFA challenge during sign-in.
 * 
 * @returns MFA verification state and method
 */
export function useMfaChallenge(): {
  challenge: import('../types').MfaChallenge | null;
  isRequired: boolean;
  verify: (code: string, method: MfaMethod) => Promise<void>;
  isLoading: boolean;
  error: ApiError | null;
} {
  const vault = useVault();
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);

  const verify = useCallback(async (code: string, method: MfaMethod) => {
    setIsLoading(true);
    setError(null);
    try {
      await vault.verifyMfa(code, method);
    } catch (err) {
      setError(err as ApiError);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [vault]);

  return {
    challenge: vault.mfaChallenge,
    isRequired: vault.authState.status === 'mfa_required',
    verify,
    isLoading,
    error,
  };
}
