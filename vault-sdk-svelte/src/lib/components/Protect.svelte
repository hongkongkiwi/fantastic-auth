<script lang="ts">
  /**
   * Protect Component
   * 
   * Protects content based on authentication state and role/permission.
   * 
   * @example
   * ```svelte
   * <Protect role="admin">
   *   <AdminPanel />
   *   
   *   {#snippet fallback()}
   *     <p>Admin access required</p>
   *   {/snippet}
   * </Protect>
   * ```
   */
  import { getVaultContext } from '../context.js';
  import type { ProtectProps, OrganizationRole } from '../types.js';
  
  let { 
    role,
    permission,
    loading,
    fallback,
    children
  }: ProtectProps = $props();
  
  const vault = getVaultContext();
  
  // Reactive state
  let isSignedIn = $state(false);
  let isLoaded = $state(false);
  let user = $state<ReturnType<typeof vault.user.subscribe> extends { subscribe(fn: (v: infer V) => void): () => void } ? V : never | null>(null);
  let organization = $state<ReturnType<typeof vault.organization.subscribe> extends { subscribe(fn: (v: infer V) => void): () => void } ? V : never | null>(null);
  
  vault.isSignedIn.subscribe(v => isSignedIn = v);
  vault.isLoaded.subscribe(v => isLoaded = v);
  vault.user.subscribe(v => user = v);
  vault.organization.subscribe(v => organization = v);
  
  // Check if user has required role
  function hasRequiredRole(requiredRole: OrganizationRole): boolean {
    if (!organization) return false;
    
    const roleHierarchy: Record<OrganizationRole, number> = {
      owner: 4,
      admin: 3,
      member: 2,
      guest: 1
    };
    
    const userRoleLevel = roleHierarchy[organization.role] || 0;
    const requiredRoleLevel = roleHierarchy[requiredRole] || 0;
    
    return userRoleLevel >= requiredRoleLevel;
  }
  
  // Derived authorization state
  let isAuthorized = $derived.by(() => {
    if (!isSignedIn || !user) return false;
    
    if (role && !hasRequiredRole(role)) return false;
    if (permission) {
      // Check permission logic here
      // This is a simplified check - expand based on your permission system
      return false;
    }
    
    return true;
  });
</script>

{#if !isLoaded}
  {#if loading}
    {@render loading()}
  {:else}
    <div class="vault-loading">Loading...</div>
  {/if}
{:else if isAuthorized}
  {@render children()}
{:else if fallback}
  {@render fallback()}
{:else}
  <div class="vault-unauthorized">
    <h2>Access Denied</h2>
    <p>You don't have permission to view this content.</p>
    <a href="/sign-in">Sign In</a>
  </div>
{/if}

<style>
  .vault-loading {
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 2rem;
    color: #6b7280;
  }
  
  .vault-unauthorized {
    text-align: center;
    padding: 2rem;
  }
  
  .vault-unauthorized h2 {
    margin: 0 0 0.5rem;
    color: #111827;
  }
  
  .vault-unauthorized p {
    margin: 0 0 1rem;
    color: #6b7280;
  }
  
  .vault-unauthorized a {
    color: #3b82f6;
    text-decoration: none;
  }
  
  .vault-unauthorized a:hover {
    text-decoration: underline;
  }
</style>
