/**
 * useOrganization Composable
 *
 * Composable for organization management.
 *
 * @example
 * ```vue
 * <script setup lang="ts">
 * import { useOrganization } from '@fantasticauth/vue';
 *
 * const {
 *   organizations,
 *   organization,
 *   setActive,
 *   create,
 *   isLoading
 * } = useOrganization();
 * </script>
 *
 * <template>
 *   <select @change="setActive(($event.target as HTMLSelectElement).value)">
 *     <option v-for="org in organizations" :key="org.id" :value="org.id">
 *       {{ org.name }}
 *     </option>
 *   </select>
 * </template>
 * ```
 */

import { ref, watch } from 'vue';
import type { Ref } from 'vue';
import { useVault } from '../plugin';
import type {
  Organization,
  OrganizationMember,
  OrganizationRole,
  UseOrganizationReturn,
  ApiError,
} from '../types';

/**
 * Composable for organization operations.
 *
 * @returns Organization state and methods
 */
export function useOrganization(): UseOrganizationReturn {
  const vault = useVault();
  const isLoading = ref(false);
  const error = ref<ApiError | null>(null);
  const members = ref<OrganizationMember[]>([]);

  // Load members when active organization changes
  watch(
    () => vault.organization.value,
    async (newOrg) => {
      if (!newOrg) {
        members.value = [];
        return;
      }

      isLoading.value = true;
      try {
        // Load members from API
        // This is a placeholder - actual implementation would call the API
        members.value = [];
      } catch (err) {
        error.value = err as ApiError;
      } finally {
        isLoading.value = false;
      }
    },
    { immediate: true }
  );

  const setActive = (orgId: string | null) => {
    vault.setActiveOrganization(orgId).catch(() => {
      // Error is already handled in vault context
    });
  };

  /**
   * Set the active organization with async handling.
   * This updates the token with new organization context.
   *
   * @param orgId - Organization ID to switch to, or null for personal workspace
   */
  const setActiveOrganization = async (orgId: string | null) => {
    isLoading.value = true;
    error.value = null;
    try {
      await vault.setActiveOrganization(orgId);
    } catch (err) {
      error.value = err as ApiError;
      throw err;
    } finally {
      isLoading.value = false;
    }
  };

  const create = async (data: { name: string; slug?: string }) => {
    isLoading.value = true;
    error.value = null;
    try {
      const org = await vault.createOrganization(data.name, data.slug);
      return org;
    } catch (err) {
      error.value = err as ApiError;
      throw err;
    } finally {
      isLoading.value = false;
    }
  };

  /**
   * Create a new organization.
   *
   * @param name - Organization name
   * @param slug - Optional organization slug (URL-friendly identifier)
   * @returns The created organization
   */
  const createOrganization = async (name: string, slug?: string) => {
    isLoading.value = true;
    error.value = null;
    try {
      const org = await vault.createOrganization(name, slug);
      return org;
    } catch (err) {
      error.value = err as ApiError;
      throw err;
    } finally {
      isLoading.value = false;
    }
  };

  const leave = async (orgId: string) => {
    isLoading.value = true;
    error.value = null;
    try {
      await vault.leaveOrganization(orgId);
    } catch (err) {
      error.value = err as ApiError;
      throw err;
    } finally {
      isLoading.value = false;
    }
  };

  const refreshMembers = async () => {
    if (!vault.organization.value) return;

    isLoading.value = true;
    error.value = null;
    try {
      // This would call the API to load members
      // const membersList = await vault.api.listOrganizationMembers(vault.organization.value.id);
      // members.value = membersList;
    } catch (err) {
      error.value = err as ApiError;
      throw err;
    } finally {
      isLoading.value = false;
    }
  };

  /**
   * Update an organization.
   *
   * @param orgId - Organization ID to update
   * @param updates - Partial organization data to update
   */
  const updateOrganization = async (orgId: string, updates: Partial<Organization>) => {
    isLoading.value = true;
    error.value = null;
    try {
      // This would call the API to update organization
      // const updated = await vault.api.updateOrganization(orgId, updates);
      // Update local state if this is the active organization
      if (vault.organization.value?.id === orgId) {
        vault.setActiveOrganization(orgId).catch(() => {
          // Error handled in context
        });
      }
      // return updated;
      return {} as Organization;
    } catch (err) {
      error.value = err as ApiError;
      throw err;
    } finally {
      isLoading.value = false;
    }
  };

  /**
   * Delete an organization.
   *
   * @param orgId - Organization ID to delete
   */
  const deleteOrganization = async (orgId: string) => {
    isLoading.value = true;
    error.value = null;
    try {
      // await vault.api.deleteOrganization(orgId);
      // Refresh organizations list
      await vault.refreshOrganizations();
      // Clear active org if it was deleted
      if (vault.organization.value?.id === orgId) {
        await vault.setActiveOrganization(null);
      }
    } catch (err) {
      error.value = err as ApiError;
      throw err;
    } finally {
      isLoading.value = false;
    }
  };

  /**
   * Invite a member to an organization.
   *
   * @param orgId - Organization ID
   * @param email - Email of the user to invite
   * @param role - Role to assign to the invited user
   */
  const inviteMember = async (orgId: string, email: string, role: OrganizationRole) => {
    isLoading.value = true;
    error.value = null;
    try {
      // await vault.api.inviteOrganizationMember(orgId, email, role);
    } catch (err) {
      error.value = err as ApiError;
      throw err;
    } finally {
      isLoading.value = false;
    }
  };

  /**
   * Remove a member from an organization.
   *
   * @param orgId - Organization ID
   * @param userId - User ID to remove
   */
  const removeMember = async (orgId: string, userId: string) => {
    isLoading.value = true;
    error.value = null;
    try {
      // await vault.api.removeOrganizationMember(orgId, userId);
      // Refresh members list if currently viewing this org
      if (vault.organization.value?.id === orgId) {
        await refreshMembers();
      }
    } catch (err) {
      error.value = err as ApiError;
      throw err;
    } finally {
      isLoading.value = false;
    }
  };

  /**
   * Update a member's role in an organization.
   *
   * @param orgId - Organization ID
   * @param userId - User ID to update
   * @param role - New role to assign
   */
  const updateMemberRole = async (orgId: string, userId: string, role: OrganizationRole) => {
    isLoading.value = true;
    error.value = null;
    try {
      // await vault.api.updateOrganizationMemberRole(orgId, userId, role);
      // Refresh members list if currently viewing this org
      if (vault.organization.value?.id === orgId) {
        await refreshMembers();
      }
    } catch (err) {
      error.value = err as ApiError;
      throw err;
    } finally {
      isLoading.value = false;
    }
  };

  return {
    organization: vault.organization,
    organizations: vault.organizations,
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
 * Composable to get the current active organization.
 *
 * @returns The current organization or null
 */
export function useActiveOrganization(): Ref<Organization | null> {
  const vault = useVault();
  return vault.organization;
}

/**
 * Composable to get the list of all user's organizations.
 *
 * @returns Array of organizations
 */
export function useOrganizationList(): Ref<Organization[]> {
  const vault = useVault();
  return vault.organizations;
}

/**
 * Composable to check if user has a specific organization role.
 *
 * @param role - The role to check for
 * @returns Boolean indicating if user has the role
 */
export function useOrganizationRole(role: string): boolean {
  const vault = useVault();

  if (!vault.organization.value) {
    return false;
  }

  return vault.organization.value.role === role;
}

/**
 * Composable to check if user is an organization admin or owner.
 *
 * @returns Boolean indicating admin status
 */
export function useIsOrgAdmin(): boolean {
  const vault = useVault();

  if (!vault.organization.value) {
    return false;
  }

  return vault.organization.value.role === 'admin' || vault.organization.value.role === 'owner';
}

/**
 * Composable to check if user is an organization owner.
 *
 * @returns Boolean indicating owner status
 */
export function useIsOrgOwner(): boolean {
  const vault = useVault();

  if (!vault.organization.value) {
    return false;
  }

  return vault.organization.value.role === 'owner';
}

/**
 * Composable to get the current organization role.
 *
 * @returns The current organization role or null
 */
export function useCurrentOrgRole(): string | null {
  const vault = useVault();
  return vault.organization.value?.role || null;
}
