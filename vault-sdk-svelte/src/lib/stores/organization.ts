/**
 * Organization Stores
 * 
 * Svelte stores and runes for organization management.
 */

import { getVaultContext } from '../context.js';
import type { Organization, OrganizationMember, ApiError, OrganizationRole } from '../types.js';

/**
 * useOrganization - Svelte 5 rune for organization state and operations
 * 
 * @example
 * ```svelte
 * <script>
 *   import { useOrganization } from '@vault/svelte';
 *   const { organization, organizations, setActive, create } = useOrganization();
 * </script>
 * 
 * <select onchange={(e) => setActive(e.currentTarget.value)}>
 *   {#each organizations as org}
 *     <option value={org.id} selected={org.id === organization?.id}>
 *       {org.name}
 *     </option>
 *   {/each}
 * </select>
 * ```
 */
export function useOrganization() {
  const vault = getVaultContext();
  
  let isLoading = $state(false);
  let error = $state<ApiError | null>(null);
  
  async function setActive(orgId: string | null): Promise<void> {
    isLoading = true;
    error = null;
    try {
      await vault.setActiveOrganization(orgId);
    } catch (e) {
      error = e as ApiError;
      throw e;
    } finally {
      isLoading = false;
    }
  }
  
  async function create(data: { name: string; slug?: string }): Promise<void> {
    isLoading = true;
    error = null;
    try {
      await vault.createOrganization(data.name, data.slug);
    } catch (e) {
      error = e as ApiError;
      throw e;
    } finally {
      isLoading = false;
    }
  }
  
  async function leave(orgId: string): Promise<void> {
    isLoading = true;
    error = null;
    try {
      await vault.leaveOrganization(orgId);
    } catch (e) {
      error = e as ApiError;
      throw e;
    } finally {
      isLoading = false;
    }
  }
  
  async function refresh(): Promise<void> {
    isLoading = true;
    error = null;
    try {
      await vault.refreshOrganizations();
    } catch (e) {
      error = e as ApiError;
      throw e;
    } finally {
      isLoading = false;
    }
  }
  
  return {
    get organization() {
      let value = $state<Organization | null>(null);
      vault.organization.subscribe(v => value = v)();
      return value;
    },
    get organizations() {
      let value = $state<Organization[]>([]);
      vault.organizations.subscribe(v => value = v)();
      return value;
    },
    get isLoaded() {
      let value = $state(false);
      vault.isLoaded.subscribe(v => value = v)();
      return value;
    },
    get isLoading() { return isLoading; },
    get error() { return error; },
    setActive,
    create,
    leave,
    refresh,
  };
}

/**
 * useOrganizationRole - Check if user has specific organization role
 * 
 * @example
 * ```svelte
 * <script>
 *   import { useOrganizationRole } from '@vault/svelte';
 *   const isAdmin = useOrganizationRole('admin');
 * </script>
 * 
 * {#if isAdmin}
 *   <AdminPanel />
 * {/if}
 * ```
 */
export function useOrganizationRole(role: OrganizationRole | OrganizationRole[]): boolean {
  const vault = getVaultContext();
  
  const org = $derived.by(() => {
    let value: Organization | null = null;
    vault.organization.subscribe(v => value = v)();
    return value;
  });
  
  if (!org) return false;
  
  const roles = Array.isArray(role) ? role : [role];
  return roles.includes(org.role);
}

/**
 * useOrganizationMembers - Manage organization members
 * 
 * @example
 * ```svelte
 * <script>
 *   import { useOrganizationMembers } from '@vault/svelte';
 *   const { members, invite, remove, updateRole } = useOrganizationMembers('org-id');
 * </script>
 * ```
 */
export function useOrganizationMembers(orgId: string) {
  const vault = getVaultContext();
  
  let members = $state<OrganizationMember[]>([]);
  let isLoading = $state(false);
  let error = $state<ApiError | null>(null);
  
  async function loadMembers(): Promise<void> {
    isLoading = true;
    error = null;
    try {
      const data = await vault.api.listOrganizationMembers(orgId);
      members = data;
    } catch (e) {
      error = e as ApiError;
      throw e;
    } finally {
      isLoading = false;
    }
  }
  
  async function invite(email: string, role: OrganizationRole): Promise<void> {
    isLoading = true;
    error = null;
    try {
      await vault.api.inviteOrganizationMember(orgId, email, role);
      await loadMembers();
    } catch (e) {
      error = e as ApiError;
      throw e;
    } finally {
      isLoading = false;
    }
  }
  
  async function remove(userId: string): Promise<void> {
    isLoading = true;
    error = null;
    try {
      await vault.api.removeOrganizationMember(orgId, userId);
      members = members.filter(m => m.userId !== userId);
    } catch (e) {
      error = e as ApiError;
      throw e;
    } finally {
      isLoading = false;
    }
  }
  
  async function updateRole(userId: string, role: OrganizationRole): Promise<void> {
    isLoading = true;
    error = null;
    try {
      await vault.api.updateOrganizationMemberRole(orgId, userId, role);
      members = members.map(m => 
        m.userId === userId ? { ...m, role } : m
      );
    } catch (e) {
      error = e as ApiError;
      throw e;
    } finally {
      isLoading = false;
    }
  }
  
  // Load members on mount
  $effect(() => {
    loadMembers();
  });
  
  return {
    get members() { return members; },
    get isLoading() { return isLoading; },
    get error() { return error; },
    invite,
    remove,
    updateRole,
    refresh: loadMembers,
  };
}
