/**
 * usePermissions Composable
 *
 * Composable for permission and role checking.
 *
 * @example
 * ```vue
 * <script setup lang="ts">
 * import { usePermissions } from '@fantasticauth/vue';
 *
 * const { has, hasRole, hasAnyRole } = usePermissions();
 * </script>
 *
 * <template>
 *   <div v-if="has('org:write')">
 *     <button>Edit Organization</button>
 *   </div>
 *   <div v-if="hasRole(['admin', 'owner'])">
 *     <button>Admin Settings</button>
 *   </div>
 * </template>
 * ```
 */

import { computed } from 'vue';
import type { Ref } from 'vue';
import { useVault } from '../plugin';
import type { PermissionCheck, UsePermissionsReturn, OrganizationRole } from '../types';

/**
 * Composable for permission and role checking.
 *
 * @returns Permission checking methods
 */
export function usePermissions(): UsePermissionsReturn {
  const vault = useVault();

  const role = computed(() => vault.organization.value?.role || null);

  const has = (permission: string): boolean => {
    // If no organization, check based on user
    if (!vault.organization.value) {
      // Default to true for personal workspace
      return true;
    }

    const userRole = vault.organization.value.role;

    // Owner has all permissions
    if (userRole === 'owner') {
      return true;
    }

    // Admin has most permissions except billing changes
    if (userRole === 'admin') {
      if (permission === 'billing:write' || permission === 'org:delete') {
        return false;
      }
      return true;
    }

    // Member has read permissions and write on own content
    if (userRole === 'member') {
      if (permission.endsWith(':read')) {
        return true;
      }
      return false;
    }

    // Guest has limited read permissions
    if (userRole === 'guest') {
      if (permission === 'org:read' || permission === 'member:read') {
        return true;
      }
      return false;
    }

    return false;
  };

  const hasRole = (role: string | string[]): boolean => {
    const userRole = vault.organization.value?.role;
    if (!userRole) return false;

    if (Array.isArray(role)) {
      return role.includes(userRole);
    }

    return userRole === role;
  };

  const hasAnyRole = (roles: string[]): boolean => {
    const userRole = vault.organization.value?.role;
    if (!userRole) return false;

    return roles.includes(userRole);
  };

  const permissions = computed(() => {
    // This would typically come from the API
    // For now, derive from role
    const perms: string[] = [];
    const userRole = vault.organization.value?.role;

    if (!userRole) return perms;

    if (userRole === 'owner') {
      return ['org:*', 'member:*', 'billing:*', 'settings:*'];
    }

    if (userRole === 'admin') {
      return [
        'org:read', 'org:write',
        'member:read', 'member:write', 'member:delete',
        'billing:read',
        'settings:read', 'settings:write',
      ];
    }

    if (userRole === 'member') {
      return ['org:read', 'member:read', 'settings:read'];
    }

    if (userRole === 'guest') {
      return ['org:read'];
    }

    return perms;
  });

  return {
    has,
    hasRole,
    hasAnyRole,
    permissions,
    role,
    isLoaded: vault.isLoaded,
  };
}

/**
 * Composable to check authorization with flexible parameters.
 *
 * @returns Authorization checking function
 */
export function useCheckAuthorization(): {
  check: (params: PermissionCheck) => boolean;
} {
  const vault = useVault();
  const permissions = usePermissions();

  const check = (params: PermissionCheck): boolean => {
    if (params.permission) {
      return permissions.has(params.permission);
    }

    if (params.role) {
      return permissions.hasRole(params.role);
    }

    if (params.anyRole && params.anyRole.length > 0) {
      return permissions.hasAnyRole(params.anyRole);
    }

    // Default to requiring signed in
    return vault.isSignedIn.value;
  };

  return { check };
}
