<script lang="ts">
  /**
   * OrganizationSwitcher Component
   * 
   * Dropdown to switch between organizations.
   * 
   * @example
   * ```svelte
   * <OrganizationSwitcher 
   *   hidePersonal={false}
   *   onSwitch={(org) => console.log('Switched to:', org)}
   * />
   * ```
   */
  import { useOrganization } from '../stores/organization.js';
  import type { OrganizationSwitcherProps, Organization } from '../types.js';
  
  let { 
    hidePersonal = false,
    onSwitch,
    className = ''
  }: OrganizationSwitcherProps = $props();
  
  const { organization, organizations, setActive, create, isLoading } = useOrganization();
  
  let isOpen = $state(false);
  let showCreateForm = $state(false);
  let newOrgName = $state('');
  
  function toggleOpen() {
    isOpen = !isOpen;
  }
  
  function closeMenu() {
    isOpen = false;
    showCreateForm = false;
    newOrgName = '';
  }
  
  async function handleSelect(orgId: string | null) {
    closeMenu();
    try {
      await setActive(orgId);
      const selected = orgId ? organizations.find(o => o.id === orgId) || null : null;
      onSwitch?.(selected);
    } catch (e) {
      // Error handled by hook
    }
  }
  
  async function handleCreate(e: Event) {
    e.preventDefault();
    if (!newOrgName.trim()) return;
    
    try {
      await create({ name: newOrgName });
      closeMenu();
    } catch (e) {
      // Error handled by hook
    }
  }
  
  function getInitials(name: string): string {
    return name
      .split(' ')
      .map(n => n[0])
      .join('')
      .toUpperCase()
      .slice(0, 2);
  }
  
  // Close menu when clicking outside
  function handleClickOutside(e: MouseEvent) {
    const target = e.target as HTMLElement;
    if (!target.closest('.vault-org-switcher')) {
      closeMenu();
    }
  }
</script>

<svelte:window onclick={handleClickOutside} />

<div class="vault-org-switcher {className}">
  <button
    type="button"
    class="vault-org-trigger"
    onclick={toggleOpen}
    aria-expanded={isOpen}
    aria-haspopup="true"
    disabled={isLoading}
  >
    {#if organization}
      {#if organization.logoUrl}
        <img src={organization.logoUrl} alt={organization.name} class="vault-org-logo" />
      {:else}
        <div class="vault-org-avatar">{getInitials(organization.name)}</div>
      {/if}
      <span class="vault-org-name">{organization.name}</span>
    {:else}
      <div class="vault-org-avatar vault-org-avatar-personal">
        <svg viewBox="0 0 20 20" fill="currentColor">
          <path fill-rule="evenodd" d="M10 9a3 3 0 100-6 3 3 0 000 6zm-7 9a7 7 0 1114 0H3z" clip-rule="evenodd" />
        </svg>
      </div>
      <span class="vault-org-name">Personal</span>
    {/if}
    
    <svg class="vault-chevron" class:vault-chevron-open={isOpen} viewBox="0 0 20 20" fill="currentColor">
      <path fill-rule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clip-rule="evenodd" />
    </svg>
  </button>
  
  {#if isOpen}
    <div class="vault-org-dropdown" role="menu">
      {#if !hidePersonal}
        <button
          type="button"
          class="vault-org-item"
          class:vault-org-item-active={!organization}
          onclick={() => handleSelect(null)}
          role="menuitem"
        >
          <div class="vault-org-avatar vault-org-avatar-personal">
            <svg viewBox="0 0 20 20" fill="currentColor">
              <path fill-rule="evenodd" d="M10 9a3 3 0 100-6 3 3 0 000 6zm-7 9a7 7 0 1114 0H3z" clip-rule="evenodd" />
            </svg>
          </div>
          <span class="vault-org-item-name">Personal Account</span>
          {#if !organization}
            <svg class="vault-check" viewBox="0 0 20 20" fill="currentColor">
              <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd" />
            </svg>
          {/if}
        </button>
        
        <div class="vault-org-divider"></div>
      {/if}
      
      <div class="vault-org-section">
        <span class="vault-org-section-title">Organizations</span>
      </div>
      
      {#each organizations as org (org.id)}
        <button
          type="button"
          class="vault-org-item"
          class:vault-org-item-active={organization?.id === org.id}
          onclick={() => handleSelect(org.id)}
          role="menuitem"
        >
          {#if org.logoUrl}
            <img src={org.logoUrl} alt={org.name} class="vault-org-logo" />
          {:else}
            <div class="vault-org-avatar">{getInitials(org.name)}</div>
          {/if}
          <div class="vault-org-item-info">
            <span class="vault-org-item-name">{org.name}</span>
            <span class="vault-org-item-role">{org.role}</span>
          </div>
          {#if organization?.id === org.id}
            <svg class="vault-check" viewBox="0 0 20 20" fill="currentColor">
              <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd" />
            </svg>
          {/if}
        </button>
      {/each}
      
      <div class="vault-org-divider"></div>
      
      {#if showCreateForm}
        <form onsubmit={handleCreate} class="vault-org-create-form">
          <input
            type="text"
            bind:value={newOrgName}
            placeholder="Organization name"
            required
            disabled={isLoading}
            class="vault-org-input"
          />
          <div class="vault-org-create-actions">
            <button
              type="button"
              class="vault-org-btn vault-org-btn-secondary"
              onclick={() => showCreateForm = false}
              disabled={isLoading}
            >
              Cancel
            </button>
            <button
              type="submit"
              class="vault-org-btn vault-org-btn-primary"
              disabled={isLoading}
            >
              {isLoading ? 'Creating...' : 'Create'}
            </button>
          </div>
        </form>
      {:else}
        <button
          type="button"
          class="vault-org-item vault-org-create"
          onclick={() => showCreateForm = true}
          role="menuitem"
        >
          <div class="vault-org-avatar vault-org-avatar-add">
            <svg viewBox="0 0 20 20" fill="currentColor">
              <path fill-rule="evenodd" d="M10 3a1 1 0 011 1v5h5a1 1 0 110 2h-5v5a1 1 0 11-2 0v-5H4a1 1 0 110-2h5V4a1 1 0 011-1z" clip-rule="evenodd" />
            </svg>
          </div>
          <span class="vault-org-item-name">Create organization</span>
        </button>
      {/if}
    </div>
  {/if}
</div>

<style>
  .vault-org-switcher {
    position: relative;
    display: inline-block;
  }
  
  .vault-org-trigger {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.5rem;
    background: white;
    border: 1px solid #e5e7eb;
    border-radius: 0.5rem;
    cursor: pointer;
    transition: all 0.15s;
  }
  
  .vault-org-trigger:hover:not(:disabled) {
    background: #f9fafb;
    border-color: #d1d5db;
  }
  
  .vault-org-trigger:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  
  .vault-org-logo {
    width: 1.75rem;
    height: 1.75rem;
    border-radius: 0.375rem;
    object-fit: cover;
  }
  
  .vault-org-avatar {
    width: 1.75rem;
    height: 1.75rem;
    display: flex;
    align-items: center;
    justify-content: center;
    background: #3b82f6;
    color: white;
    font-size: 0.625rem;
    font-weight: 600;
    border-radius: 0.375rem;
  }
  
  .vault-org-avatar-personal {
    background: #f3f4f6;
    color: #6b7280;
  }
  
  .vault-org-avatar-personal svg {
    width: 1rem;
    height: 1rem;
  }
  
  .vault-org-avatar-add {
    background: #f3f4f6;
    color: #6b7280;
  }
  
  .vault-org-avatar-add svg {
    width: 1rem;
    height: 1rem;
  }
  
  .vault-org-name {
    font-size: 0.875rem;
    font-weight: 500;
    color: #374151;
    max-width: 150px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  
  .vault-chevron {
    width: 1rem;
    height: 1rem;
    color: #9ca3af;
    margin-left: auto;
    transition: transform 0.15s;
  }
  
  .vault-chevron-open {
    transform: rotate(180deg);
  }
  
  .vault-org-dropdown {
    position: absolute;
    right: 0;
    top: calc(100% + 0.25rem);
    min-width: 280px;
    max-height: 400px;
    overflow-y: auto;
    background: white;
    border: 1px solid #e5e7eb;
    border-radius: 0.5rem;
    box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
    z-index: 50;
  }
  
  .vault-org-section {
    padding: 0.5rem 0.75rem;
  }
  
  .vault-org-section-title {
    font-size: 0.75rem;
    font-weight: 500;
    color: #6b7280;
    text-transform: uppercase;
    letter-spacing: 0.025em;
  }
  
  .vault-org-item {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    width: 100%;
    padding: 0.625rem 0.75rem;
    background: none;
    border: none;
    text-align: left;
    cursor: pointer;
    transition: background-color 0.15s;
  }
  
  .vault-org-item:hover {
    background: #f3f4f6;
  }
  
  .vault-org-item-active {
    background: #eff6ff;
  }
  
  .vault-org-item-info {
    display: flex;
    flex-direction: column;
    flex: 1;
    min-width: 0;
  }
  
  .vault-org-item-name {
    font-size: 0.875rem;
    font-weight: 500;
    color: #111827;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  
  .vault-org-item-role {
    font-size: 0.75rem;
    color: #6b7280;
    text-transform: capitalize;
  }
  
  .vault-check {
    width: 1.25rem;
    height: 1.25rem;
    color: #3b82f6;
    flex-shrink: 0;
  }
  
  .vault-org-divider {
    height: 1px;
    background: #e5e7eb;
    margin: 0.25rem 0;
  }
  
  .vault-org-create {
    color: #3b82f6;
  }
  
  .vault-org-create-form {
    padding: 0.75rem;
  }
  
  .vault-org-input {
    width: 100%;
    padding: 0.5rem 0.75rem;
    margin-bottom: 0.75rem;
    border: 1px solid #d1d5db;
    border-radius: 0.375rem;
    font-size: 0.875rem;
  }
  
  .vault-org-input:focus {
    outline: none;
    border-color: #3b82f6;
  }
  
  .vault-org-create-actions {
    display: flex;
    gap: 0.5rem;
    justify-content: flex-end;
  }
  
  .vault-org-btn {
    padding: 0.375rem 0.75rem;
    border-radius: 0.375rem;
    font-size: 0.875rem;
    font-weight: 500;
    cursor: pointer;
  }
  
  .vault-org-btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  
  .vault-org-btn-primary {
    background: #3b82f6;
    border: none;
    color: white;
  }
  
  .vault-org-btn-primary:hover:not(:disabled) {
    background: #2563eb;
  }
  
  .vault-org-btn-secondary {
    background: white;
    border: 1px solid #d1d5db;
    color: #374151;
  }
  
  .vault-org-btn-secondary:hover:not(:disabled) {
    background: #f9fafb;
  }
</style>
