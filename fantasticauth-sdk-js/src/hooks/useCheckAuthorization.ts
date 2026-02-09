/**
 * useCheckAuthorization Hook
 * 
 * Hook for declarative permission and role checking.
 * 
 * @example
 * ```tsx
 * function ProtectedComponent() {
 *   const { check } = useCheckAuthorization();
 *   
 *   // Check specific permission
 *   const canDeleteOrg = check({ permission: 'org:delete' });
 *   
 *   // Check specific role
 *   const isAdmin = check({ role: 'admin' });
 *   
 *   // Check any of multiple roles
 *   const isAdminOrOwner = check({ anyRole: ['admin', 'owner'] });
 *   
 *   return (
 *     <div>
 *       {canDeleteOrg && <DeleteButton />}
 *       {isAdminOrOwner && <AdminControls />}
 *     </div>
 *   );
 * }
 * ```
 */

import { useCallback } from 'react';
import { useVault } from '../context/VaultContext';
import { PermissionCheck, UseCheckAuthorizationReturn, OrganizationRole, Permission } from '../types';

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
 * Hook for checking authorization with a unified check function.
 * 
 * @returns Authorization checking function
 */
export function useCheckAuthorization(): UseCheckAuthorizationReturn {
  const vault = useVault();

  /**
   * Check authorization based on permission or role criteria.
   * 
   * @param params - Permission check parameters
   * @returns Boolean indicating if authorized
   */
  const check = useCallback((params: PermissionCheck): boolean => {
    const currentRole = vault.organization?.role;
    
    if (!currentRole) {
      return false;
    }

    // Check specific permission
    if (params.permission) {
      const permissions = ROLE_PERMISSIONS[currentRole] || [];
      return permissions.includes(params.permission);
    }

    // Check specific role
    if (params.role) {
      return currentRole === params.role;
    }

    // Check any of multiple roles
    if (params.anyRole && params.anyRole.length > 0) {
      return params.anyRole.includes(currentRole);
    }

    // If no criteria specified, default to true (user is in an org)
    return true;
  }, [vault.organization?.role]);

  return { check };
}
