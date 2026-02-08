/**
 * Vault Vue SDK Composables
 *
 * Vue 3 Composition API composables for Vault authentication.
 */

// Auth composables
export {
  useAuth,
  useAuthState,
  useHasRole,
  useRequireAuth,
} from './useAuth';

// User composables
export {
  useUser,
  useUpdateUser,
  useUserManager,
} from './useUser';

// Session composables
export {
  useSession,
  useToken,
  useSessionId,
} from './useSession';

// Sign in/up composables
export {
  useSignIn,
} from './useSignIn';

export {
  useSignUp,
} from './useSignUp';

// WebAuthn composables
export {
  useWebAuthn,
  useIsWebAuthnSupported,
} from './useWebAuthn';

// MFA composables
export {
  useMfa,
  useIsMfaEnabled,
  useMfaMethods,
} from './useMfa';

// Organization composables
export {
  useOrganization,
  useActiveOrganization,
  useOrganizationList,
  useOrganizationRole,
  useIsOrgAdmin,
  useIsOrgOwner,
  useCurrentOrgRole,
} from './useOrganization';

// Permission composables
export {
  usePermissions,
  useCheckAuthorization,
} from './usePermissions';

// Session management composables
export {
  useSessions,
} from './useSessions';
