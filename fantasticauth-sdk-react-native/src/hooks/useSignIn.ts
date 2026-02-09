/**
 * useSignIn Hook
 * 
 * Hook for sign-in functionality with loading and error states.
 * Includes OAuth and biometric sign-in support.
 * 
 * @example
 * ```tsx
 * function SignInScreen() {
 *   const { signIn, isLoading, error, signInWithOAuth } = useSignIn();
 *   
 *   const handleEmailSignIn = async (email: string, password: string) => {
 *     try {
 *       await signIn({ email, password });
 *       navigation.navigate('Home');
 *     } catch (err) {
 *       // Error is already in `error` state
 *     }
 *   };
 *   
 *   const handleGoogleSignIn = () => {
 *     signInWithOAuth({ provider: 'google' });
 *   };
 *   
 *   return (
 *     <View>
 *       <SignInForm onSubmit={handleEmailSignIn} loading={isLoading} />
 *       {error && <ErrorMessage error={error} />}
 *       <GoogleButton onPress={handleGoogleSignIn} />
 *     </View>
 *   );
 * }
 * ```
 */

import { useCallback, useState } from 'react';
import { useVault } from '../VaultProvider';
import { 
  SignInOptions, 
  MagicLinkOptions, 
  OAuthOptions, 
  UseSignInReturn,
  ApiError 
} from '../types';
import { useOAuthDeepLink } from '../deep-linking';
import { authenticateWithBiometrics, createBiometricSignature } from '../biometric';
import { isBiometricEnabled } from '../storage';

/**
 * Hook for sign-in operations.
 * Provides loading states, error handling, and OAuth support.
 * 
 * @returns Sign-in methods and state
 */
export function useSignIn(): UseSignInReturn {
  const vault = useVault();
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  
  const { startOAuth } = useOAuthDeepLink({
    apiUrl: vault.config.apiUrl,
    tenantId: vault.config.tenantId,
    oauthRedirectScheme: vault.config.oauthRedirectScheme,
  });

  const resetError = useCallback(() => {
    setError(null);
  }, []);

  const signIn = useCallback(async (options: SignInOptions) => {
    setIsLoading(true);
    setError(null);
    try {
      await vault.signIn(options);
    } catch (err) {
      setError(err as ApiError);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [vault]);

  const signInWithMagicLink = useCallback(async (options: MagicLinkOptions) => {
    setIsLoading(true);
    setError(null);
    try {
      await vault.signInWithMagicLink(options);
    } catch (err) {
      setError(err as ApiError);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [vault]);

  const signInWithOAuth = useCallback(async (options: OAuthOptions) => {
    setIsLoading(true);
    setError(null);
    try {
      const baseUrl = vault.config.apiUrl.replace(/\/$/, '');
      const scheme = vault.config.oauthRedirectScheme || 'vault';
      const redirectUri = `${scheme}://oauth/${options.provider}`;
      
      // Build OAuth URL
      const params = new URLSearchParams({
        provider: options.provider,
        redirect_uri: redirectUri,
        ...(options.redirectUrl && { final_redirect: options.redirectUrl }),
      });
      
      const oauthUrl = `${baseUrl}/api/v1/auth/oauth/${options.provider}?${params.toString()}`;
      
      // Open in-app browser
      await startOAuth(oauthUrl);
    } catch (err) {
      setError(err as ApiError);
      setIsLoading(false);
      throw err;
    }
  }, [vault, startOAuth]);

  const signInWithBiometrics = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    
    try {
      const enabled = await isBiometricEnabled();
      if (!enabled) {
        throw { 
          message: 'Biometric sign-in not enabled', 
          code: 'biometric_not_enabled' 
        } as ApiError;
      }

      // Authenticate with biometrics
      const authResult = await authenticateWithBiometrics('Sign in with biometrics');
      if (!authResult.success) {
        throw { 
          message: authResult.error || 'Biometric authentication failed', 
          code: 'biometric_failed' 
        } as ApiError;
      }

      // Get challenge from server
      const challenge = await vault.api.request<string>('/api/v1/auth/biometric/challenge', {
        method: 'POST',
      });

      // Create signature with biometric
      const signResult = await createBiometricSignature(challenge, 'Sign in');
      if (!signResult.success || !signResult.signature) {
        throw { 
          message: 'Failed to create biometric signature', 
          code: 'biometric_signature_failed' 
        } as ApiError;
      }

      // Complete sign in with challenge and signature
      await vault.signInWithBiometric(challenge, signResult.signature);
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
    signIn,
    signInWithMagicLink,
    signInWithOAuth,
    signInWithBiometrics,
    resetError,
  };
}
