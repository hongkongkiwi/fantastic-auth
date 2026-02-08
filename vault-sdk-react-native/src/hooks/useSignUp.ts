/**
 * useSignUp Hook
 * 
 * Hook for sign-up functionality with loading and error states.
 * Includes OAuth sign-up support.
 * 
 * @example
 * ```tsx
 * function SignUpScreen() {
 *   const { signUp, isLoading, error } = useSignUp();
 *   
 *   const handleSubmit = async (email: string, password: string, name: string) => {
 *     try {
 *       await signUp({ email, password, name });
 *       navigation.navigate('Home');
 *     } catch (err) {
 *       // Error is already in `error` state
 *     }
 *   };
 *   
 *   return (
 *     <View>
 *       <SignUpForm onSubmit={handleSubmit} loading={isLoading} />
 *       {error && <ErrorMessage error={error} />}
 *     </View>
 *   );
 * }
 * ```
 */

import { useCallback, useState } from 'react';
import { useVault } from '../VaultProvider';
import { 
  SignUpOptions, 
  OAuthOptions, 
  UseSignUpReturn,
  ApiError 
} from '../types';
import { useOAuthDeepLink } from '../deep-linking';

/**
 * Hook for sign-up operations.
 * Provides loading states and error handling.
 * 
 * @returns Sign-up methods and state
 */
export function useSignUp(): UseSignUpReturn {
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

  const signUp = useCallback(async (options: SignUpOptions) => {
    setIsLoading(true);
    setError(null);
    try {
      await vault.signUp(options);
    } catch (err) {
      setError(err as ApiError);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [vault]);

  const signUpWithOAuth = useCallback(async (options: OAuthOptions) => {
    setIsLoading(true);
    setError(null);
    try {
      const baseUrl = vault.config.apiUrl.replace(/\/$/, '');
      const scheme = vault.config.oauthRedirectScheme || 'vault';
      const redirectUri = `${scheme}://oauth/${options.provider}`;
      
      // Build OAuth URL with signup flag
      const params = new URLSearchParams({
        provider: options.provider,
        redirect_uri: redirectUri,
        signup: 'true',
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

  return {
    isLoading,
    error,
    signUp,
    signUpWithOAuth,
    resetError,
  };
}
