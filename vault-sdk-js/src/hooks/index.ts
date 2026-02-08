/**
 * Vault SDK Hooks
 * 
 * React hooks for the Vault authentication SDK.
 */

// Auth hooks
export { useAuth, useAuthState, useHasRole, useRequireAuth } from './useAuth';

// User hooks
export { useUser, useUpdateUser, useUserManager } from './useUser';

// Session hooks
export { useSession, useToken, useSessionId } from './useSession';
export { useSessions } from './useSessions';

// Sign in/up hooks
export { useSignIn } from './useSignIn';
export { useSignUp } from './useSignUp';

// WebAuthn hooks
export { useWebAuthn, useIsWebAuthnSupported } from './useWebAuthn';

// MFA hooks
export { useMfa, useMfaChallenge } from './useMfa';

// Organization hooks
export { 
  useOrganization, 
  useActiveOrganization, 
  useOrganizationRole,
  useIsOrgAdmin,
} from './useOrganization';

// Permission hooks
export { usePermissions } from './usePermissions';

// Authorization hooks
export { useCheckAuthorization } from './useCheckAuthorization';

// Billing hooks
export { useBilling, useSubscription, useUsage } from './useBilling';
