/**
 * useOrganization Hook
 * 
 * Hook for organization management in React Native.
 * 
 * @example
 * ```tsx
 * function OrganizationScreen() {
 *   const { 
 *     organizations, 
 *     organization, 
 *     setActive,
 *     create 
 *   } = useOrganization();
 *   
 *   return (
 *     <View>
 *       <Text>Current: {organization?.name || 'Personal'}</Text>
 *       {organizations.map(org => (
 *         <TouchableOpacity 
 *           key={org.id}
 *           onPress={() => setActive(org.id)}
 *         >
 *           <Text>{org.name}</Text>
 *         </TouchableOpacity>
 *       ))}
 *     </View>
 *   );
 * }
 * ```
 */

import { useCallback, useEffect, useState } from 'react';
import { useVault } from '../VaultProvider';
import { 
  Organization, 
  OrganizationMember, 
  OrganizationRole,
  UseOrganizationReturn,
  ApiError 
} from '../types';

/**
 * Hook for organization operations.
 * 
 * @returns Organization state and methods
 */
export function useOrganization(): UseOrganizationReturn {
  const vault = useVault();
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [members, setMembers] = useState<OrganizationMember[]>([]);

  // Load organizations on mount
  useEffect(() => {
    if (vault.isSignedIn) {
      vault.refreshOrganizations();
    }
  }, [vault.isSignedIn]);

  // Load members when active organization changes
  useEffect(() => {
    const loadMembers = async () => {
      if (!vault.organization) {
        setMembers([]);
        return;
      }

      setIsLoading(true);
      try {
        const membersList = await vault.api.listOrganizationMembers(vault.organization.id);
        setMembers(membersList);
      } catch (err) {
        setError(err as ApiError);
      } finally {
        setIsLoading(false);
      }
    };

    loadMembers();
  }, [vault.organization, vault.api]);

  const setActive = useCallback((orgId: string | null) => {
    vault.setActiveOrganization(orgId).catch(() => {
      // Error is already handled in vault context
    });
  }, [vault]);

  const setActiveOrganization = useCallback(async (orgId: string | null) => {
    setIsLoading(true);
    setError(null);
    try {
      await vault.setActiveOrganization(orgId);
    } catch (err) {
      setError(err as ApiError);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [vault]);

  const create = useCallback(async (data: { name: string; slug?: string }) => {
    setIsLoading(true);
    setError(null);
    try {
      const org = await vault.createOrganization(data.name, data.slug);
      return org;
    } catch (err) {
      setError(err as ApiError);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [vault]);

  const createOrganization = useCallback(async (name: string, slug?: string) => {
    setIsLoading(true);
    setError(null);
    try {
      const org = await vault.createOrganization(name, slug);
      return org;
    } catch (err) {
      setError(err as ApiError);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [vault]);

  const leave = useCallback(async (orgId: string) => {
    setIsLoading(true);
    setError(null);
    try {
      await vault.leaveOrganization(orgId);
    } catch (err) {
      setError(err as ApiError);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [vault]);

  const refreshMembers = useCallback(async () => {
    if (!vault.organization) return;

    setIsLoading(true);
    setError(null);
    try {
      const membersList = await vault.api.listOrganizationMembers(vault.organization.id);
      setMembers(membersList);
    } catch (err) {
      setError(err as ApiError);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [vault.organization, vault.api]);

  const updateOrganization = useCallback(async (orgId: string, updates: Partial<Organization>) => {
    setIsLoading(true);
    setError(null);
    try {
      const updated = await vault.api.updateOrganization(orgId, updates);
      // Update local state if this is the active organization
      if (vault.organization?.id === orgId) {
        vault.setActiveOrganization(orgId).catch(() => {
          // Error handled in context
        });
      }
      // Refresh organizations list
      await vault.refreshOrganizations();
      return updated;
    } catch (err) {
      setError(err as ApiError);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [vault]);

  const deleteOrganization = useCallback(async (orgId: string) => {
    setIsLoading(true);
    setError(null);
    try {
      await vault.api.deleteOrganization(orgId);
      // Refresh organizations list
      await vault.refreshOrganizations();
      // Clear active org if it was deleted
      if (vault.organization?.id === orgId) {
        await vault.setActiveOrganization(null);
      }
    } catch (err) {
      setError(err as ApiError);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [vault]);

  const inviteMember = useCallback(async (orgId: string, email: string, role: OrganizationRole) => {
    setIsLoading(true);
    setError(null);
    try {
      await vault.api.inviteOrganizationMember(orgId, email, role);
    } catch (err) {
      setError(err as ApiError);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [vault.api]);

  const removeMember = useCallback(async (orgId: string, userId: string) => {
    setIsLoading(true);
    setError(null);
    try {
      await vault.api.removeOrganizationMember(orgId, userId);
      // Refresh members list if currently viewing this org
      if (vault.organization?.id === orgId) {
        await refreshMembers();
      }
    } catch (err) {
      setError(err as ApiError);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [vault.api, vault.organization, refreshMembers]);

  const updateMemberRole = useCallback(async (orgId: string, userId: string, role: OrganizationRole) => {
    setIsLoading(true);
    setError(null);
    try {
      await vault.api.updateOrganizationMemberRole(orgId, userId, role);
      // Refresh members list if currently viewing this org
      if (vault.organization?.id === orgId) {
        await refreshMembers();
      }
    } catch (err) {
      setError(err as ApiError);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [vault.api, vault.organization, refreshMembers]);

  return {
    organization: vault.organization,
    organizations: vault.organizations,
    organizationList: vault.organizations,
    isLoaded: vault.isLoaded,
    isLoading,
    members,
    setActive,
    setActiveOrganization,
    create,
    createOrganization,
    leave,
    refreshMembers,
    updateOrganization,
    deleteOrganization,
    inviteMember,
    removeMember,
    updateMemberRole,
  };
}

/**
 * Hook to get the current active organization.
 * 
 * @returns The current organization or null
 */
export function useActiveOrganization(): Organization | null {
  const vault = useVault();
  return vault.organization;
}

/**
 * Hook to get the list of all user's organizations.
 * 
 * @returns Array of organizations
 */
export function useOrganizationList(): Organization[] {
  const vault = useVault();
  return vault.organizations;
}

/**
 * Hook to check if user has a specific organization role.
 * 
 * @param role - The role to check for
 * @returns Boolean indicating if user has the role
 */
export function useOrganizationRole(role: string): boolean {
  const vault = useVault();
  
  if (!vault.organization) {
    return false;
  }
  
  return vault.organization.role === role;
}

/**
 * Hook to check if user is an organization admin or owner.
 * 
 * @returns Boolean indicating admin status
 */
export function useIsOrgAdmin(): boolean {
  const vault = useVault();
  
  if (!vault.organization) {
    return false;
  }
  
  return vault.organization.role === 'admin' || vault.organization.role === 'owner';
}

/**
 * Hook to check if user is an organization owner.
 * 
 * @returns Boolean indicating owner status
 */
export function useIsOrgOwner(): boolean {
  const vault = useVault();
  
  if (!vault.organization) {
    return false;
  }
  
  return vault.organization.role === 'owner';
}
