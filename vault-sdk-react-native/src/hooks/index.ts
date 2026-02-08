/**
 * React Hooks
 * 
 * Custom React hooks for Vault authentication in React Native.
 * 
 * @example
 * ```tsx
 * import { useAuth, useUser, useSession } from '@vault/react-native';
 * 
 * function Profile() {
 *   const { isSignedIn, user, signOut } = useAuth();
 *   const { update } = useUserManager();
 *   const { getToken } = useSession();
 *   
 *   // Use hooks...
 * }
 * ```
 */

// Auth hooks
export {
  useAuth,
  useAuthState,
  useHasRole,
  useRequireAuth,
} from './useAuth';

// User hooks
export {
  useUser,
  useUserManager,
} from './useUser';

// Session hooks
export {
  useSession,
  useToken,
  useSessionId,
  useSessions,
} from './useSession';

// Sign in/up hooks
export {
  useSignIn,
} from './useSignIn';

export {
  useSignUp,
} from './useSignUp';

// WebAuthn hooks
export {
  useWebAuthn,
  useIsWebAuthnSupported,
  useWebAuthnCredentials,
} from './useWebAuthn';

// Organization hooks
export {
  useOrganization,
  useActiveOrganization,
  useOrganizationList,
  useOrganizationRole,
  useIsOrgAdmin,
  useIsOrgOwner,
} from './useOrganization';

// Re-export from biometric module
export {
  useBiometricAuth,
} from '../biometric';

// Re-export from deep-linking module
export {
  useOAuthDeepLink,
} from '../deep-linking';
