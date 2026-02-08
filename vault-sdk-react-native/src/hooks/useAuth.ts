/**
 * useAuth Hook
 * 
 * Primary hook for authentication state and actions in React Native.
 * Includes biometric unlock support.
 * 
 * @example
 * ```tsx
 * function App() {
 *   const { isSignedIn, user, signOut, isLocked, unlockWithBiometrics } = useAuth();
 *   
 *   if (isLocked) {
 *     return (
 *       <BiometricUnlock 
 *         onUnlock={unlockWithBiometrics}
 *       />
 *     );
 *   }
 *   
 *   if (!isSignedIn) {
 *     return <SignInScreen />;
 *   }
 *   
 *   return (
 *     <View>
 *       <Text>Hello {user?.email}</Text>
 *       <Button onPress={signOut}>Sign out</Button>
 *     </View>
 *   );
 * }
 * ```
 */

import { useCallback } from 'react';
import { useVault } from '../VaultProvider';
import { 
  SignInOptions, 
  MagicLinkOptions, 
  OAuthOptions, 
  SignUpOptions,
  UseAuthReturn,
} from '../types';
import { authenticateWithBiometrics } from '../biometric';
import { isBiometricEnabled } from '../storage';

/**
 * Hook to access authentication state and methods.
 * Must be used within a VaultProvider.
 * 
 * @returns Authentication state and methods including biometric support
 */
export function useAuth(): UseAuthReturn {
  const vault = useVault();

  const unlockWithBiometrics = useCallback(async (): Promise<boolean> => {
    const enabled = await isBiometricEnabled();
    if (!enabled) {
      vault.setLocked(false);
      return true;
    }

    const result = await authenticateWithBiometrics('Unlock the app');
    if (result.success) {
      vault.setLocked(false);
      return true;
    }
    return false;
  }, [vault]);

  const lockApp = useCallback(() => {
    vault.setLocked(true);
  }, [vault]);

  return {
    // State
    isLoaded: vault.isLoaded,
    isSignedIn: vault.isSignedIn,
    user: vault.user,
    session: vault.session,
    organization: vault.organization,
    isLocked: vault.isLocked,
    
    // Actions
    signIn: vault.signIn,
    signInWithMagicLink: vault.signInWithMagicLink,
    signInWithOAuth: vault.signInWithOAuth,
    signUp: vault.signUp,
    signOut: vault.signOut,
    
    // Biometric
    unlockWithBiometrics,
    lockApp,
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
  isLocked: boolean;
} {
  const vault = useVault();
  
  return {
    isLoaded: vault.isLoaded,
    isSignedIn: vault.isSignedIn,
    isLocked: vault.isLocked,
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
  user: NonNullable<UseAuthReturn['user']>;
  session: NonNullable<UseAuthReturn['session']>;
  organization: UseAuthReturn['organization'];
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
