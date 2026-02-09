/**
 * useSignIn Hook
 * 
 * Hook for sign-in functionality with loading and error states.
 * 
 * @example
 * ```tsx
 * function SignInPage() {
 *   const { signIn, isLoading, error } = useSignIn();
 *   
 *   const handleSubmit = async (e) => {
 *     e.preventDefault();
 *     const formData = new FormData(e.target);
 *     try {
 *       await signIn({
 *         email: formData.get('email'),
 *         password: formData.get('password'),
 *       });
 *     } catch (err) {
 *       // Handle error
 *     }
 *   };
 *   
 *   return (
 *     <form onSubmit={handleSubmit}>
 *       <input name="email" type="email" />
 *       <input name="password" type="password" />
 *       {error && <p>{error.message}</p>}
 *       <button disabled={isLoading}>
 *         {isLoading ? 'Signing in...' : 'Sign In'}
 *       </button>
 *     </form>
 *   );
 * }
 * ```
 */

import { useCallback, useState } from 'react';
import { useVault } from '../context/VaultContext';
import { 
  SignInOptions, 
  MagicLinkOptions, 
  OAuthOptions, 
  UseSignInReturn,
  ApiError 
} from '../types';

/**
 * Hook for sign-in operations.
 * Provides loading states and error handling.
 * 
 * @returns Sign-in methods and state
 */
export function useSignIn(): UseSignInReturn {
  const vault = useVault();
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);

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
      await vault.signInWithOAuth(options);
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
    resetError,
  };
}
