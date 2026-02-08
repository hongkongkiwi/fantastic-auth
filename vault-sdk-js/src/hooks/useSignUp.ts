/**
 * useSignUp Hook
 * 
 * Hook for sign-up functionality with loading and error states.
 * 
 * @example
 * ```tsx
 * function SignUpPage() {
 *   const { signUp, isLoading, error } = useSignUp();
 *   
 *   const handleSubmit = async (e) => {
 *     e.preventDefault();
 *     const formData = new FormData(e.target);
 *     try {
 *       await signUp({
 *         email: formData.get('email'),
 *         password: formData.get('password'),
 *         name: formData.get('name'),
 *       });
 *     } catch (err) {
 *       // Handle error
 *     }
 *   };
 *   
 *   return (
 *     <form onSubmit={handleSubmit}>
 *       <input name="name" placeholder="Full Name" />
 *       <input name="email" type="email" />
 *       <input name="password" type="password" />
 *       {error && <p>{error.message}</p>}
 *       <button disabled={isLoading}>
 *         {isLoading ? 'Creating account...' : 'Sign Up'}
 *       </button>
 *     </form>
 *   );
 * }
 * ```
 */

import { useCallback, useState } from 'react';
import { useVault } from '../context/VaultContext';
import { 
  SignUpOptions, 
  OAuthOptions, 
  UseSignUpReturn,
  ApiError 
} from '../types';

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
    signUp,
    signUpWithOAuth,
    resetError,
  };
}
