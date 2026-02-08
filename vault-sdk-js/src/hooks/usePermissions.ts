/**
 * usePermissions Hook
 * 
 * Hook for checking user permissions based on organization role.
 * 
 * @example
 * ```tsx
 * function AdminPanel() {
 *   const { has, hasRole, permissions, role, isLoaded } = usePermissions();
 *   
 *   if (!isLoaded) return <Loading />;
 *   
 *   if (has('org:delete')) {
 *     return <DeleteOrgButton />;
 *   }
 *   
 *   if (hasRole('admin')) {
 *     return <AdminDashboard />;
 *   }
 *   
 *   return <MemberView />;
 * }
 * ```
 */

import { useMemo } from 'react';
import { useVault } from '../context/VaultContext';
import { OrganizationRole, UsePermissionsReturn, Permission } from '../types';

// Permission mapping for each role
const ROLE_PERMISSIONS: Record<OrganizationRole, Permission[]> = {
  owner: [
    'org:read',
    'org:write',
    'org:delete',
    'member:read',
    'member:write',
    'member:delete',
    'billing:read',
    'billing:write',
    'settings:read',
    'settings:write',
  ],
  admin: [
    'org:read',
    'org:write',
    'member:read',
    'member:write',
    'member:delete',
    'billing:read',
    'settings:read',
    'settings:write',
  ],
  member: [
    'org:read',
    'member:read',
    'settings:read',
  ],
  guest: [
    'org:read',
  ],
};

/**
 * Hook for checking user permissions derived from organization role.
 * 
 * @returns Permission checking functions and current role info
 */
export function usePermissions(): UsePermissionsReturn {
  const vault = useVault();

  const { role, permissions } = useMemo(() => {
    const currentRole = vault.organization?.role || null;
    const perms = currentRole ? ROLE_PERMISSIONS[currentRole] : [];
    return { role: currentRole, permissions: perms };
  }, [vault.organization?.role]);

  /**
   * Check if user has a specific permission
   */
  const has = useMemo(() => {
    return (permission: Permission): boolean => {
      if (!role) return false;
      return permissions.includes(permission);
    };
  }, [role, permissions]);

  /**
   * Check if user has a specific role
   */
  const hasRole = useMemo(() => {
    return (checkRole: string | string[]): boolean => {
      if (!role) return false;
      if (Array.isArray(checkRole)) {
        return checkRole.includes(role);
      }
      return role === checkRole;
    };
  }, [role]);

  /**
   * Check if user has any of the specified roles
   */
  const hasAnyRole = useMemo(() => {
    return (roles: string[]): boolean => {
      if (!role) return false;
      return roles.includes(role);
    };
  }, [role]);

  return {
    has,
    hasRole,
    hasAnyRole,
    permissions,
    role,
    isLoaded: vault.isLoaded,
  };
}
