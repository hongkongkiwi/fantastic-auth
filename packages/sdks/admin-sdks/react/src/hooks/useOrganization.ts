/**
 * useOrganization Hook
 * 
 * Hook for organization management operations.
 */

import { useCallback, useMemo, useState } from 'react';
import { useOrganization as useVaultOrganization, Organization } from '@fantasticauth/react';
import type { UseOrganizationReturn, AuthError } from '../types';

/**
 * Hook for organization management.
 * 
 * @returns Organization data and management functions
 * 
 * @example
 * ```tsx
 * function OrgSelector() {
 *   const { organizations, setActive, create } = useOrganization();
 *   
 *   return (
 *     <select onChange={(e) => setActive(e.target.value)}>
 *       {organizations.map(org => (
 *         <option key={org.id} value={org.id}>{org.name}</option>
 *       ))}
 *     </select>
 *   );
 * }
 * ```
 */
export function useOrganization(): UseOrganizationReturn {
  const vaultOrg = useVaultOrganization();
  const [error, setError] = useState<AuthError | null>(null);

  const convertError = useCallback((err: unknown): AuthError => {
    if (err && typeof err === 'object') {
      const apiError = err as { code?: string; message?: string };
      return {
        code: apiError.code || 'unknown_error',
        message: apiError.message || 'An unexpected error occurred',
      };
    }
    return {
      code: 'unknown_error',
      message: err instanceof Error ? err.message : 'An unexpected error occurred',
    };
  }, []);

  const setActive = useCallback(async (orgId: string | null) => {
    try {
      setError(null);
      await vaultOrg.setActiveOrganization(orgId);
    } catch (err) {
      const authError = convertError(err);
      setError(authError);
      throw authError;
    }
  }, [vaultOrg, convertError]);

  const create = useCallback(async (name: string, slug?: string) => {
    try {
      setError(null);
      return await vaultOrg.createOrganization(name, slug);
    } catch (err) {
      const authError = convertError(err);
      setError(authError);
      throw authError;
    }
  }, [vaultOrg, convertError]);

  const leave = useCallback(async (orgId: string) => {
    try {
      setError(null);
      await vaultOrg.leave(orgId);
    } catch (err) {
      const authError = convertError(err);
      setError(authError);
      throw authError;
    }
  }, [vaultOrg, convertError]);

  const refresh = useCallback(async () => {
    try {
      setError(null);
      await vaultOrg.refreshMembers();
    } catch (err) {
      const authError = convertError(err);
      setError(authError);
      throw authError;
    }
  }, [vaultOrg, convertError]);

  return useMemo(() => ({
    organization: vaultOrg.organization,
    organizations: vaultOrg.organizations,
    isLoading: vaultOrg.isLoading,
    setActive,
    create,
    leave,
    refresh,
    error,
  }), [
    vaultOrg.organization,
    vaultOrg.organizations,
    vaultOrg.isLoading,
    setActive,
    create,
    leave,
    refresh,
    error,
  ]);
}

/**
 * Hook to check if user has an active organization
 * 
 * @returns Boolean indicating if user has an active organization
 */
export function useHasActiveOrganization(): boolean {
  const { organization } = useOrganization();
  return organization !== null;
}

/**
 * Hook to get the user's organization role
 * 
 * @returns Organization role or null
 */
export function useOrganizationRole(): string | null {
  const { organization } = useOrganization();
  return organization?.role || null;
}

/**
 * Hook to check if user is an organization admin
 * 
 * @returns Boolean indicating if user is an admin
 */
export function useIsOrgAdmin(): boolean {
  const role = useOrganizationRole();
  return role === 'owner' || role === 'admin';
}

/**
 * Hook to get organization count
 * 
 * @returns Number of organizations user belongs to
 */
export function useOrganizationCount(): number {
  const { organizations } = useOrganization();
  return organizations.length;
}
