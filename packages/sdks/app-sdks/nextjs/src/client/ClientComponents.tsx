'use client';

/**
 * Client-side hooks and components for Vault authentication
 * 
 * All exports from this file are marked with 'use client' directive
 * and can be used in client components.
 */

import * as React from 'react';
import { useVaultContext } from './VaultProvider';
import type { User, Session } from '../types';

/**
 * Hook to access authentication state and methods
 * 
 * @returns Authentication state and sign out method
 * 
 * @example
 * ```tsx
 * 'use client';
 * 
 * import { useAuth } from '@fantasticauth/nextjs/client';
 * 
 * export function AuthButton() {
 *   const { isSignedIn, signOut, isLoaded } = useAuth();
 *   
 *   if (!isLoaded) return <button disabled>Loading...</button>;
 *   
 *   if (isSignedIn) {
 *     return <button onClick={() => signOut()}>Sign Out</button>;
 *   }
 *   
 *   return <a href="/sign-in">Sign In</a>;
 * }
 * ```
 */
export function useAuth(): {
  isLoaded: boolean;
  isSignedIn: boolean;
  userId: string | null;
  orgId: string | null;
  orgRole: string | null;
  signOut: () => Promise<void>;
  getToken: () => Promise<string | null>;
} {
  const context = useVaultContext();

  return {
    isLoaded: context.isLoaded,
    isSignedIn: context.isSignedIn,
    userId: context.user?.id || null,
    orgId: context.orgId,
    orgRole: context.orgRole,
    signOut: context.signOut,
    getToken: context.getToken,
  };
}

/**
 * Hook to access the current user
 * 
 * @returns User object and loading state
 * 
 * @example
 * ```tsx
 * 'use client';
 * 
 * import { useUser } from '@fantasticauth/nextjs/client';
 * 
 * export function UserProfile() {
 *   const { user, isLoaded } = useUser();
 *   
 *   if (!isLoaded) return <div>Loading...</div>;
 *   if (!user) return <div>Not signed in</div>;
 *   
 *   return (
 *     <div>
 *       <img src={user.imageUrl} alt={user.name} />
 *       <h2>{user.name}</h2>
 *       <p>{user.email}</p>
 *     </div>
 *   );
 * }
 * ```
 */
export function useUser(): {
  isLoaded: boolean;
  isSignedIn: boolean;
  user: User | null;
} {
  const context = useVaultContext();

  return {
    isLoaded: context.isLoaded,
    isSignedIn: context.isSignedIn,
    user: context.user,
  };
}

/**
 * Hook to access the current session
 * 
 * @returns Session object and loading state
 * 
 * @example
 * ```tsx
 * 'use client';
 * 
 * import { useSession } from '@fantasticauth/nextjs/client';
 * 
 * export function SessionInfo() {
 *   const { session, isLoaded } = useSession();
 *   
 *   if (!isLoaded) return <div>Loading...</div>;
 *   if (!session) return <div>No session</div>;
 *   
 *   return <div>Session expires: {session.expiresAt.toLocaleString()}</div>;
 * }
 * ```
 */
export function useSession(): {
  isLoaded: boolean;
  session: Session | null;
} {
  const context = useVaultContext();

  return {
    isLoaded: context.isLoaded,
    session: context.session,
  };
}

/**
 * Hook to access organization information
 * 
 * @returns Organization ID and role
 * 
 * @example
 * ```tsx
 * 'use client';
 * 
 * import { useOrganization } from '@fantasticauth/nextjs/client';
 * 
 * export function OrgBadge() {
 *   const { orgId, orgRole, isLoaded } = useOrganization();
 *   
 *   if (!isLoaded) return null;
 *   if (!orgId) return <span>Personal</span>;
 *   
 *   return (
 *     <span>
 *       Org: {orgId} ({orgRole})
 *     </span>
 *   );
 * }
 * ```
 */
export function useOrganization(): {
  isLoaded: boolean;
  orgId: string | null;
  orgRole: string | null;
  isSignedIn: boolean;
} {
  const context = useVaultContext();

  return {
    isLoaded: context.isLoaded,
    orgId: context.orgId,
    orgRole: context.orgRole,
    isSignedIn: context.isSignedIn,
  };
}

/**
 * Hook to check if user has required role
 * 
 * @param allowedRoles - Array of allowed roles
 * @returns boolean indicating if user has one of the allowed roles
 * 
 * @example
 * ```tsx
 * 'use client';
 * 
 * import { useHasRole } from '@fantasticauth/nextjs/client';
 * 
 * export function AdminOnly({ children }) {
 *   const hasAdminRole = useHasRole(['admin', 'owner']);
 *   
 *   if (!hasAdminRole) return <div>Access denied</div>;
 *   
 *   return <>{children}</>;
 * }
 * ```
 */
export function useHasRole(allowedRoles: string[]): boolean {
  const { orgRole, isLoaded, isSignedIn } = useOrganization();

  if (!isLoaded || !isSignedIn || !orgRole) {
    return false;
  }

  return allowedRoles.includes(orgRole);
}

// Re-export for convenience
export { useVaultContext };
export { useVaultContext as useFantasticauthContext };
