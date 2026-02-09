<script lang="ts">
  /**
   * SignIn Component
   * 
   * A complete sign-in form with email/password, OAuth, and magic link support.
   * 
   * @example
   * ```svelte
   * <SignIn 
   *   redirectUrl="/dashboard"
   *   oauthProviders={['google', 'github']}
   *   showMagicLink={true}
   * />
   * ```
   */
  import { useSignIn } from '../stores/auth.js';
  import type { SignInProps, ApiError } from '../types.js';
  
  let { 
    redirectUrl,
    onSignIn,
    onError,
    showMagicLink = false,
    showForgotPassword = true,
    oauthProviders = [],
    showWebAuthn = false,
    className = ''
  }: SignInProps = $props();
  
  // Form state
  let email = $state('');
  let password = $state('');
  let showMagicLinkForm = $state(false);
  
  // Use sign in hook
  const { signIn, signInWithMagicLink, signInWithOAuth, isLoading, error, resetError } = useSignIn();
  
  // Handle email/password sign in
  async function handleSubmit(e: Event) {
    e.preventDefault();
    resetError();
    
    try {
      if (showMagicLinkForm) {
        await signInWithMagicLink({ email, redirectUrl });
        // Show success message
        alert('Magic link sent! Check your email.');
      } else {
        await signIn({ email, password });
        onSignIn?.();
      }
    } catch (e) {
      onError?.(e as ApiError);
    }
  }
  
  // Handle OAuth sign in
  async function handleOAuth(provider: string) {
    resetError();
    
    try {
      await signInWithOAuth({ provider, redirectUrl });
      // Note: This will redirect, so onSignIn won't be called for OAuth
    } catch (e) {
      onError?.(e as ApiError);
    }
  }
  
  // Toggle between password and magic link
  function toggleMagicLink() {
    showMagicLinkForm = !showMagicLinkForm;
    resetError();
  }
  
  // Handle forgot password click
  function handleForgotPassword() {
    // Navigate to forgot password page or show modal
    window.location.href = '/forgot-password';
  }
</script>

<div class="vault-signin {className}">
  {#if oauthProviders.length > 0 && !showMagicLinkForm}
    <div class="vault-oauth-buttons">
      {#each oauthProviders as provider}
        <button
          type="button"
          class="vault-btn vault-btn-oauth vault-btn-{provider}"
          onclick={() => handleOAuth(provider)}
          disabled={isLoading}
        >
          {#if provider === 'google'}
            <svg viewBox="0 0 24 24" class="vault-icon"><path fill="currentColor" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/><path fill="currentColor" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/><path fill="currentColor" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/><path fill="currentColor" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/></svg>
            Continue with Google
          {:else if provider === 'github'}
            <svg viewBox="0 0 24 24" class="vault-icon"><path fill="currentColor" d="M12 1C5.92 1 1 5.92 1 12c0 4.87 3.15 8.99 7.52 10.44.55.1.75-.24.75-.53 0-.26-.01-.96-.01-1.88-3.06.66-3.71-1.48-3.71-1.48-.5-1.27-1.22-1.61-1.22-1.61-1-.68.08-.66.08-.66 1.1.08 1.68 1.13 1.68 1.13.98 1.68 2.57 1.2 3.2.91.1-.71.38-1.2.7-1.47-2.44-.28-5.01-1.22-5.01-5.44 0-1.2.43-2.19 1.13-2.96-.11-.28-.49-1.39.11-2.9 0 0 .92-.29 3.02 1.13.88-.25 1.82-.37 2.76-.37.93 0 1.88.13 2.76.37 2.09-1.42 3.01-1.13 3.01-1.13.6 1.51.22 2.62.11 2.9.71.77 1.13 1.76 1.13 2.96 0 4.23-2.57 5.16-5.02 5.42.4.34.75 1.01.75 2.04 0 1.47-.01 2.66-.01 3.02 0 .29.2.64.76.53C19.86 20.99 23 16.87 23 12c0-6.08-4.92-11-11-11z"/></svg>
            Continue with GitHub
          {:else if provider === 'microsoft'}
            <svg viewBox="0 0 21 21" class="vault-icon"><path fill="currentColor" d="M1 1h9v9H1V1zm10 0h9v9h-9V1zM1 11h9v9H1v-9zm10 0h9v9h-9v-9z"/></svg>
            Continue with Microsoft
          {:else}
            Continue with {provider}
          {/if}
        </button>
      {/each}
    </div>
    
    <div class="vault-divider">
      <span>or</span>
    </div>
  {/if}
  
  <form onsubmit={handleSubmit} class="vault-form">
    <div class="vault-form-group">
      <label for="email" class="vault-label">Email</label>
      <input
        id="email"
        type="email"
        bind:value={email}
        placeholder="name@example.com"
        required
        disabled={isLoading}
        class="vault-input"
      />
    </div>
    
    {#if !showMagicLinkForm}
      <div class="vault-form-group">
        <label for="password" class="vault-label">Password</label>
        <input
          id="password"
          type="password"
          bind:value={password}
          placeholder="Enter your password"
          required
          disabled={isLoading}
          class="vault-input"
        />
      </div>
    {/if}
    
    {#if error}
      <div class="vault-error" role="alert">
        {error.message}
      </div>
    {/if}
    
    <button
      type="submit"
      disabled={isLoading}
      class="vault-btn vault-btn-primary"
    >
      {#if isLoading}
        {#if showMagicLinkForm}
          Sending magic link...
        {:else}
          Signing in...
        {/if}
      {:else}
        {#if showMagicLinkForm}
          Send magic link
        {:else}
          Sign in
        {/if}
      {/if}
    </button>
  </form>
  
  <div class="vault-footer">
    {#if showMagicLink}
      <button
        type="button"
        class="vault-link"
        onclick={toggleMagicLink}
      >
        {#if showMagicLinkForm}
          Use password instead
        {:else}
          Sign in with magic link
        {/if}
      </button>
    {/if}
    
    {#if showForgotPassword && !showMagicLinkForm}
      <button
        type="button"
        class="vault-link"
        onclick={handleForgotPassword}
      >
        Forgot password?
      </button>
    {/if}
  </div>
</div>

<style>
  .vault-signin {
    max-width: 400px;
    margin: 0 auto;
    padding: 1.5rem;
    font-family: system-ui, -apple-system, sans-serif;
  }
  
  .vault-oauth-buttons {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
    margin-bottom: 1.5rem;
  }
  
  .vault-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
    padding: 0.625rem 1rem;
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
  
  .vault-btn-oauth {
    background: white;
    border: 1px solid #e5e7eb;
    color: #374151;
  }
  
  .vault-btn-oauth:hover:not(:disabled) {
    background: #f9fafb;
  }
  
  .vault-btn-primary {
    width: 100%;
    background: #111827;
    border: none;
    color: white;
  }
  
  .vault-btn-primary:hover:not(:disabled) {
    background: #1f2937;
  }
  
  .vault-icon {
    width: 1.25rem;
    height: 1.25rem;
  }
  
  .vault-divider {
    display: flex;
    align-items: center;
    margin: 1.5rem 0;
    color: #6b7280;
    font-size: 0.875rem;
  }
  
  .vault-divider::before,
  .vault-divider::after {
    content: '';
    flex: 1;
    height: 1px;
    background: #e5e7eb;
  }
  
  .vault-divider span {
    padding: 0 1rem;
  }
  
  .vault-form {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }
  
  .vault-form-group {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }
  
  .vault-label {
    font-size: 0.875rem;
    font-weight: 500;
    color: #374151;
  }
  
  .vault-input {
    padding: 0.5rem 0.75rem;
    border: 1px solid #d1d5db;
    border-radius: 0.375rem;
    font-size: 0.875rem;
    transition: border-color 0.15s;
  }
  
  .vault-input:focus {
    outline: none;
    border-color: #3b82f6;
    ring: 2px solid #bfdbfe;
  }
  
  .vault-input:disabled {
    background: #f3f4f6;
    cursor: not-allowed;
  }
  
  .vault-error {
    padding: 0.75rem;
    background: #fef2f2;
    border: 1px solid #fecaca;
    border-radius: 0.375rem;
    color: #dc2626;
    font-size: 0.875rem;
  }
  
  .vault-footer {
    display: flex;
    justify-content: space-between;
    margin-top: 1rem;
    padding-top: 1rem;
    border-top: 1px solid #e5e7eb;
  }
  
  .vault-link {
    background: none;
    border: none;
    color: #3b82f6;
    font-size: 0.875rem;
    cursor: pointer;
    text-decoration: underline;
  }
  
  .vault-link:hover {
    color: #2563eb;
  }
</style>
