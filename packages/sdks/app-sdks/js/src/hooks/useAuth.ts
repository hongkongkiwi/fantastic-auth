/**
 * useAuth Hook
 * 
 * Primary hook for authentication state and actions.
 * 
 * @example
 * ```tsx
 * function App() {
 *   const { isSignedIn, user, signOut } = useAuth();
 *   
 *   if (!isSignedIn) {
 *     return <SignIn />;
 *   }
 *   
 *   return (
 *     <div>
 *       <p>Hello {user?.email}</p>
 *       <button onClick={signOut}>Sign out</button>
 *     </div>
 *   );
 * }
 * ```
 */

import { useVault } from '../context/VaultContext';
import { 
  SignInOptions, 
  MagicLinkOptions, 
  OAuthOptions, 
  SignUpOptions,
  UseAuthReturn,
  User,
  Session,
  Organization 
} from '../types';

/**
 * Hook to access authentication state and methods.
 * Must be used within a VaultProvider.
 * 
 * @returns Authentication state and methods
 */
export function useAuth(): UseAuthReturn {
  const vault = useVault();

  return {
    // State
    isLoaded: vault.isLoaded,
    isSignedIn: vault.isSignedIn,
    user: vault.user,
    session: vault.session,
    organization: vault.organization,
    
    // Actions
    signIn: vault.signIn,
    signInWithMagicLink: vault.signInWithMagicLink,
    signInWithOAuth: vault.signInWithOAuth,
    signUp: vault.signUp,
    signOut: vault.signOut,
  };
}

/**
 * Hook to get the current authentication state only.
 * Useful when you only need to check if user is signed in.
 * 
 * @returns Object with isLoaded and isSignedIn booleans
 */
export function useAuthState(): { 
  isLoaded: boolean; 
  isSignedIn: boolean;
} {
  const vault = useVault();
  
  return {
    isLoaded: vault.isLoaded,
    isSignedIn: vault.isSignedIn,
  };
}

/**
 * Hook to check if the current user has a specific role.
 * 
 * @param role - The role to check for
 * @returns Boolean indicating if user has the role
 */
export function useHasRole(role: string): boolean {
  const vault = useVault();
  
  if (!vault.isSignedIn || !vault.user) {
    return false;
  }
  
  // Check organization role
  if (vault.organization?.role === role) {
    return true;
  }
  
  return false;
}

/**
 * Hook to require authentication.
 * Returns the user or throws if not authenticated.
 * 
 * @returns The current user
 * @throws Error if not authenticated
 */
export function useRequireAuth(): {
  user: User;
  session: Session;
  organization: Organization | null;
} {
  const vault = useVault();
  
  if (!vault.isSignedIn || !vault.user || !vault.session) {
    throw new Error('Authentication required');
  }
  
  return {
    user: vault.user,
    session: vault.session,
    organization: vault.organization,
  };
}
