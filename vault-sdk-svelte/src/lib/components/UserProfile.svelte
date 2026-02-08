<script lang="ts">
  /**
   * UserProfile Component
   * 
   * Displays and allows editing of user profile information.
   * 
   * @example
   * ```svelte
   * <UserProfile onUpdate={(user) => console.log('Updated:', user)} />
   * ```
   */
  import { useUser } from '../stores/user.js';
  import type { UserProfileProps } from '../types.js';
  
  let { 
    onUpdate,
    className = ''
  }: UserProfileProps = $props();
  
  const { user, update, isLoading, error } = useUser();
  
  // Form state
  let name = $state('');
  let email = $state('');
  let givenName = $state('');
  let familyName = $state('');
  let phoneNumber = $state('');
  let isEditing = $state(false);
  
  // Initialize form values when user data is available
  $effect(() => {
    if (user) {
      name = user.profile?.name || '';
      email = user.email || '';
      givenName = user.profile?.givenName || '';
      familyName = user.profile?.familyName || '';
      phoneNumber = user.profile?.phoneNumber || '';
    }
  });
  
  async function handleSubmit(e: Event) {
    e.preventDefault();
    
    try {
      await update({
        profile: {
          name: name || undefined,
          givenName: givenName || undefined,
          familyName: familyName || undefined,
          phoneNumber: phoneNumber || undefined,
        }
      });
      isEditing = false;
      onUpdate?.(user!);
    } catch (e) {
      // Error is handled by the hook
    }
  }
  
  function handleCancel() {
    // Reset form values
    if (user) {
      name = user.profile?.name || '';
      email = user.email || '';
      givenName = user.profile?.givenName || '';
      familyName = user.profile?.familyName || '';
      phoneNumber = user.profile?.phoneNumber || '';
    }
    isEditing = false;
  }
</script>

{#if user}
  <div class="vault-user-profile {className}">
    <div class="vault-profile-header">
      <div class="vault-avatar-container">
        {#if user.profile?.picture}
          <img 
            src={user.profile.picture} 
            alt={user.profile.name || user.email}
            class="vault-avatar"
          />
        {:else}
          <div class="vault-avatar vault-avatar-fallback">
            {(user.profile?.name || user.email).charAt(0).toUpperCase()}
          </div>
        {/if}
        <button type="button" class="vault-avatar-edit">
          <svg viewBox="0 0 20 20" fill="currentColor">
            <path d="M13.586 3.586a2 2 0 112.828 2.828l-.793.793-2.828-2.828.793-.793zM11.379 5.793L3 14.172V17h2.828l8.38-8.379-2.83-2.828z" />
          </svg>
        </button>
      </div>
      
      <div class="vault-profile-info">
        <h2>{user.profile?.name || user.email}</h2>
        <p>{user.email}</p>
        {#if user.emailVerified}
          <span class="vault-badge vault-badge-verified">Verified</span>
        {:else}
          <span class="vault-badge vault-badge-unverified">Unverified</span>
        {/if}
      </div>
    </div>
    
    {#if error}
      <div class="vault-error" role="alert">
        {error.message}
      </div>
    {/if}
    
    {#if isEditing}
      <form onsubmit={handleSubmit} class="vault-form">
        <div class="vault-form-grid">
          <div class="vault-form-group">
            <label for="givenName">First name</label>
            <input
              id="givenName"
              type="text"
              bind:value={givenName}
              disabled={isLoading}
            />
          </div>
          
          <div class="vault-form-group">
            <label for="familyName">Last name</label>
            <input
              id="familyName"
              type="text"
              bind:value={familyName}
              disabled={isLoading}
            />
          </div>
        </div>
        
        <div class="vault-form-group">
          <label for="name">Display name</label>
          <input
            id="name"
            type="text"
            bind:value={name}
            disabled={isLoading}
          />
        </div>
        
        <div class="vault-form-group">
          <label for="email">Email</label>
          <input
            id="email"
            type="email"
            bind:value={email}
            disabled={true}
          />
          <p class="vault-hint">Email cannot be changed</p>
        </div>
        
        <div class="vault-form-group">
          <label for="phoneNumber">Phone number</label>
          <input
            id="phoneNumber"
            type="tel"
            bind:value={phoneNumber}
            disabled={isLoading}
          />
        </div>
        
        <div class="vault-form-actions">
          <button
            type="button"
            class="vault-btn vault-btn-secondary"
            onclick={handleCancel}
            disabled={isLoading}
          >
            Cancel
          </button>
          <button
            type="submit"
            class="vault-btn vault-btn-primary"
            disabled={isLoading}
          >
            {#if isLoading}
              Saving...
            {:else}
              Save changes
            {/if}
          </button>
        </div>
      </form>
    {:else}
      <div class="vault-profile-details">
        <div class="vault-detail-row">
          <span class="vault-detail-label">First name</span>
          <span class="vault-detail-value">{user.profile?.givenName || '-'}</span>
        </div>
        <div class="vault-detail-row">
          <span class="vault-detail-label">Last name</span>
          <span class="vault-detail-value">{user.profile?.familyName || '-'}</span>
        </div>
        <div class="vault-detail-row">
          <span class="vault-detail-label">Phone</span>
          <span class="vault-detail-value">{user.profile?.phoneNumber || '-'}</span>
        </div>
        <div class="vault-detail-row">
          <span class="vault-detail-label">Member since</span>
          <span class="vault-detail-value">
            {new Date(user.createdAt).toLocaleDateString()}
          </span>
        </div>
      </div>
      
      <button
        type="button"
        class="vault-btn vault-btn-secondary"
        onclick={() => isEditing = true}
      >
        Edit profile
      </button>
    {/if}
  </div>
{/if}

<style>
  .vault-user-profile {
    max-width: 600px;
    padding: 1.5rem;
    font-family: system-ui, -apple-system, sans-serif;
  }
  
  .vault-profile-header {
    display: flex;
    align-items: center;
    gap: 1rem;
    margin-bottom: 1.5rem;
  }
  
  .vault-avatar-container {
    position: relative;
  }
  
  .vault-avatar {
    width: 5rem;
    height: 5rem;
    border-radius: 9999px;
    object-fit: cover;
  }
  
  .vault-avatar-fallback {
    display: flex;
    align-items: center;
    justify-content: center;
    background: #3b82f6;
    color: white;
    font-size: 2rem;
    font-weight: 600;
  }
  
  .vault-avatar-edit {
    position: absolute;
    bottom: 0;
    right: 0;
    width: 2rem;
    height: 2rem;
    display: flex;
    align-items: center;
    justify-content: center;
    background: white;
    border: 1px solid #e5e7eb;
    border-radius: 9999px;
    cursor: pointer;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
  }
  
  .vault-avatar-edit svg {
    width: 1rem;
    height: 1rem;
    color: #6b7280;
  }
  
  .vault-avatar-edit:hover {
    background: #f3f4f6;
  }
  
  .vault-profile-info h2 {
    margin: 0;
    font-size: 1.25rem;
    font-weight: 600;
    color: #111827;
  }
  
  .vault-profile-info p {
    margin: 0.25rem 0 0;
    color: #6b7280;
    font-size: 0.875rem;
  }
  
  .vault-badge {
    display: inline-flex;
    align-items: center;
    padding: 0.125rem 0.5rem;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: 500;
    margin-top: 0.5rem;
  }
  
  .vault-badge-verified {
    background: #d1fae5;
    color: #065f46;
  }
  
  .vault-badge-unverified {
    background: #fef3c7;
    color: #92400e;
  }
  
  .vault-error {
    padding: 0.75rem;
    margin-bottom: 1rem;
    background: #fef2f2;
    border: 1px solid #fecaca;
    border-radius: 0.375rem;
    color: #dc2626;
    font-size: 0.875rem;
  }
  
  .vault-form {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }
  
  .vault-form-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
  }
  
  @media (max-width: 480px) {
    .vault-form-grid {
      grid-template-columns: 1fr;
    }
  }
  
  .vault-form-group {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }
  
  .vault-form-group label {
    font-size: 0.875rem;
    font-weight: 500;
    color: #374151;
  }
  
  .vault-form-group input {
    padding: 0.5rem 0.75rem;
    border: 1px solid #d1d5db;
    border-radius: 0.375rem;
    font-size: 0.875rem;
  }
  
  .vault-form-group input:focus {
    outline: none;
    border-color: #3b82f6;
  }
  
  .vault-form-group input:disabled {
    background: #f3f4f6;
    cursor: not-allowed;
  }
  
  .vault-hint {
    font-size: 0.75rem;
    color: #6b7280;
    margin: 0;
  }
  
  .vault-form-actions {
    display: flex;
    gap: 0.75rem;
    justify-content: flex-end;
    margin-top: 0.5rem;
  }
  
  .vault-btn {
    padding: 0.5rem 1rem;
    border-radius: 0.375rem;
    font-size: 0.875rem;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.15s;
  }
  
  .vault-btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  
  .vault-btn-primary {
    background: #111827;
    border: none;
    color: white;
  }
  
  .vault-btn-primary:hover:not(:disabled) {
    background: #1f2937;
  }
  
  .vault-btn-secondary {
    background: white;
    border: 1px solid #d1d5db;
    color: #374151;
  }
  
  .vault-btn-secondary:hover:not(:disabled) {
    background: #f9fafb;
  }
  
  .vault-profile-details {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
    margin-bottom: 1.5rem;
  }
  
  .vault-detail-row {
    display: flex;
    justify-content: space-between;
    padding: 0.75rem 0;
    border-bottom: 1px solid #e5e7eb;
  }
  
  .vault-detail-label {
    color: #6b7280;
    font-size: 0.875rem;
  }
  
  .vault-detail-value {
    color: #111827;
    font-size: 0.875rem;
    font-weight: 500;
  }
</style>
