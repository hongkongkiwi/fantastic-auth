/**
 * Vault React UI Hooks
 * 
 * Pre-built hooks for common authentication and user management tasks.
 */

// Auth hooks
export { 
  useAuth,
  useIsAuthLoading,
  useIsAuthenticated,
  useCurrentUser,
  useLogin,
  useSignup,
  useLogout,
  usePasswordReset,
} from './useAuth';

export type { UseAuthReturn } from '../types';

// User hooks
export { 
  useUser,
  useUserProfile,
  useIsEmailVerified,
  useIsMfaEnabled,
} from './useUser';

export type { UseUserReturn } from '../types';

// Organization hooks
export { 
  useOrganization,
  useHasActiveOrganization,
  useOrganizationRole,
  useIsOrgAdmin,
  useOrganizationCount,
} from './useOrganization';

export type { UseOrganizationReturn } from '../types';
