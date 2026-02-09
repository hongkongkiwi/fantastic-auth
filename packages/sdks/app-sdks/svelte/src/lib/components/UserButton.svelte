<script lang="ts">
  /**
   * UserButton Component
   * 
   * Displays user avatar with dropdown menu for account actions.
   * 
   * @example
   * ```svelte
   * <UserButton 
   *   showName={true}
   *   showManageAccount={true}
   * />
   * ```
   */
  import { useAuth } from '../stores/auth.js';
  import type { UserButtonProps } from '../types.js';
  
  let { 
    showName = false,
    avatarUrl,
    onSignOut,
    menuItems = [],
    showManageAccount = true,
    className = ''
  }: UserButtonProps = $props();
  
  const { user, signOut } = useAuth();
  
  let isOpen = $state(false);
  
  function toggleMenu() {
    isOpen = !isOpen;
  }
  
  function closeMenu() {
    isOpen = false;
  }
  
  async function handleSignOut() {
    closeMenu();
    await signOut();
    onSignOut?.();
  }
  
  function getInitials(name: string | undefined): string {
    if (!name) return '?';
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
    if (!target.closest('.vault-user-button')) {
      closeMenu();
    }
  }
  
  // Handle escape key
  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') {
      closeMenu();
    }
  }
</script>

<svelte:window onclick={handleClickOutside} onkeydown={handleKeydown} />

{#if user}
  <div class="vault-user-button {className}">
    <button
      type="button"
      class="vault-user-button-trigger"
      onclick={toggleMenu}
      aria-expanded={isOpen}
      aria-haspopup="true"
    >
      {#if avatarUrl || user.profile?.picture}
        <img 
          src={avatarUrl || user.profile?.picture} 
          alt={user.profile?.name || user.email}
          class="vault-avatar vault-avatar-image"
        />
      {:else}
        <div class="vault-avatar vault-avatar-fallback">
          {getInitials(user.profile?.name)}
        </div>
      {/if}
      
      {#if showName}
        <span class="vault-user-name">
          {user.profile?.name || user.email}
        </span>
      {/if}
      
      <svg class="vault-chevron" class:vault-chevron-open={isOpen} viewBox="0 0 20 20" fill="currentColor">
        <path fill-rule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clip-rule="evenodd" />
      </svg>
    </button>
    
    {#if isOpen}
      <div class="vault-dropdown" role="menu">
        <div class="vault-dropdown-header">
          <p class="vault-dropdown-email">{user.email}</p>
          {#if user.profile?.name}
            <p class="vault-dropdown-name">{user.profile.name}</p>
          {/if}
        </div>
        
        <div class="vault-dropdown-divider"></div>
        
        {#if showManageAccount}
          <a href="/account" class="vault-dropdown-item" role="menuitem">
            <svg viewBox="0 0 20 20" fill="currentColor">
              <path fill-rule="evenodd" d="M10 9a3 3 0 100-6 3 3 0 000 6zm-7 9a7 7 0 1114 0H3z" clip-rule="evenodd" />
            </svg>
            Manage account
          </a>
        {/if}
        
        {#each menuItems as item}
          <button
            type="button"
            class="vault-dropdown-item"
            onclick={() => { closeMenu(); item.onClick(); }}
            role="menuitem"
          >
            {item.label}
          </button>
        {/each}
        
        <div class="vault-dropdown-divider"></div>
        
        <button
          type="button"
          class="vault-dropdown-item vault-dropdown-item-danger"
          onclick={handleSignOut}
          role="menuitem"
        >
          <svg viewBox="0 0 20 20" fill="currentColor">
            <path fill-rule="evenodd" d="M3 3a1 1 0 00-1 1v12a1 1 0 102 0V4a1 1 0 00-1-1zm10.293 9.293a1 1 0 001.414 1.414l3-3a1 1 0 000-1.414l-3-3a1 1 0 10-1.414 1.414L14.586 9H7a1 1 0 100 2h7.586l-1.293 1.293z" clip-rule="evenodd" />
          </svg>
          Sign out
        </button>
      </div>
    {/if}
  </div>
{/if}

<style>
  .vault-user-button {
    position: relative;
    display: inline-block;
  }
  
  .vault-user-button-trigger {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.375rem;
    background: none;
    border: none;
    border-radius: 0.5rem;
    cursor: pointer;
    transition: background-color 0.15s;
  }
  
  .vault-user-button-trigger:hover {
    background: #f3f4f6;
  }
  
  .vault-avatar {
    width: 2rem;
    height: 2rem;
    border-radius: 9999px;
    flex-shrink: 0;
  }
  
  .vault-avatar-image {
    object-fit: cover;
  }
  
  .vault-avatar-fallback {
    display: flex;
    align-items: center;
    justify-content: center;
    background: #3b82f6;
    color: white;
    font-size: 0.75rem;
    font-weight: 600;
  }
  
  .vault-user-name {
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
    transition: transform 0.15s;
  }
  
  .vault-chevron-open {
    transform: rotate(180deg);
  }
  
  .vault-dropdown {
    position: absolute;
    right: 0;
    top: calc(100% + 0.5rem);
    min-width: 200px;
    background: white;
    border: 1px solid #e5e7eb;
    border-radius: 0.5rem;
    box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
    z-index: 50;
  }
  
  .vault-dropdown-header {
    padding: 0.75rem 1rem;
  }
  
  .vault-dropdown-email {
    font-size: 0.875rem;
    font-weight: 500;
    color: #111827;
    margin: 0;
  }
  
  .vault-dropdown-name {
    font-size: 0.75rem;
    color: #6b7280;
    margin: 0.25rem 0 0;
  }
  
  .vault-dropdown-divider {
    height: 1px;
    background: #e5e7eb;
    margin: 0.25rem 0;
  }
  
  .vault-dropdown-item {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    width: 100%;
    padding: 0.5rem 1rem;
    background: none;
    border: none;
    font-size: 0.875rem;
    color: #374151;
    text-align: left;
    text-decoration: none;
    cursor: pointer;
    transition: background-color 0.15s;
  }
  
  .vault-dropdown-item:hover {
    background: #f3f4f6;
  }
  
  .vault-dropdown-item svg {
    width: 1.25rem;
    height: 1.25rem;
    color: #9ca3af;
  }
  
  .vault-dropdown-item-danger {
    color: #dc2626;
  }
  
  .vault-dropdown-item-danger:hover {
    background: #fef2f2;
  }
  
  .vault-dropdown-item-danger svg {
    color: #dc2626;
  }
</style>
