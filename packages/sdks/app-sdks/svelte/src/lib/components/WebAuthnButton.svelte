<script lang="ts">
  /**
   * WebAuthnButton Component
   * 
   * Button for WebAuthn/passkey authentication.
   * 
   * @example
   * ```svelte
   * <WebAuthnButton 
   *   mode="signin"
   *   label="Sign in with passkey"
   *   onSuccess={() => console.log('Signed in!')}
   * />
   * ```
   */
  import { getVaultContext } from '../context.js';
  import type { WebAuthnButtonProps, ApiError, WebAuthnCredential } from '../types.js';
  
  let { 
    mode = 'signin',
    label,
    onSuccess,
    onError,
    className = ''
  }: WebAuthnButtonProps = $props();
  
  const vault = getVaultContext();
  
  let isLoading = $state(false);
  let error = $state<ApiError | null>(null);
  
  // Check if WebAuthn is supported
  const isSupported = typeof window !== 'undefined' && 
    typeof window.PublicKeyCredential !== 'undefined';
  
  async function handleClick() {
    if (!isSupported) {
      onError?.({ code: 'webauthn_not_supported', message: 'WebAuthn is not supported in this browser' });
      return;
    }
    
    isLoading = true;
    error = null;
    
    try {
      if (mode === 'signin' || mode === 'signup') {
        await authenticate();
      } else if (mode === 'link') {
        await register();
      }
      onSuccess?.();
    } catch (e) {
      error = e as ApiError;
      onError?.(error);
    } finally {
      isLoading = false;
    }
  }
  
  async function authenticate(): Promise<void> {
    // Begin authentication
    const options = await vault.api.beginWebAuthnAuthentication();
    
    // Convert challenge from base64url to ArrayBuffer
    const challenge = base64urlToBuffer(options.challenge);
    const allowCredentials = [];
    
    const credential = await navigator.credentials.get({
      publicKey: {
        ...options,
        challenge,
        allowCredentials,
      }
    }) as PublicKeyCredential;
    
    if (!credential) {
      throw new Error('No credential returned');
    }
    
    // Finish authentication
    await vault.api.finishWebAuthnAuthentication(serializeCredential(credential));
    
    // Update auth state
    await vault.reloadUser();
  }
  
  async function register(): Promise<void> {
    // Begin registration
    const options = await vault.api.beginWebAuthnRegistration();
    
    // Convert base64url strings to ArrayBuffers
    const challenge = base64urlToBuffer(options.challenge);
    const userId = base64urlToBuffer(options.user.id);
    
    const credential = await navigator.credentials.create({
      publicKey: {
        ...options,
        challenge,
        user: {
          ...options.user,
          id: userId,
        },
      }
    }) as PublicKeyCredential;
    
    if (!credential) {
      throw new Error('No credential created');
    }
    
    // Finish registration
    await vault.api.finishWebAuthnRegistration(serializeCredential(credential));
    
    // Update user
    await vault.reloadUser();
  }
  
  function base64urlToBuffer(base64url: string): ArrayBuffer {
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }
  
  function bufferToBase64url(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }
  
  function serializeCredential(credential: PublicKeyCredential): unknown {
    if (credential.response instanceof AuthenticatorAttestationResponse) {
      return {
        id: credential.id,
        rawId: bufferToBase64url(credential.rawId),
        type: credential.type,
        response: {
          clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
          attestationObject: bufferToBase64url(credential.response.attestationObject),
        }
      };
    } else {
      return {
        id: credential.id,
        rawId: bufferToBase64url(credential.rawId),
        type: credential.type,
        response: {
          clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
          authenticatorData: bufferToBase64url((credential.response as AuthenticatorAssertionResponse).authenticatorData),
          signature: bufferToBase64url((credential.response as AuthenticatorAssertionResponse).signature),
          userHandle: (credential.response as AuthenticatorAssertionResponse).userHandle 
            ? bufferToBase64url((credential.response as AuthenticatorAssertionResponse).userHandle!)
            : null,
        }
      };
    }
  }
  
  // Default labels based on mode
  const defaultLabel = {
    signin: 'Sign in with passkey',
    signup: 'Sign up with passkey',
    link: 'Add passkey'
  }[mode];
</script>

{#if isSupported}
  <button
    type="button"
    class="vault-webauthn-btn {className}"
    onclick={handleClick}
    disabled={isLoading}
  >
    <svg class="vault-webauthn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      <path d="M12 2a5 5 0 0 1 5 5v2a5 5 0 0 1-10 0V7a5 5 0 0 1 5-5z" />
      <path d="M12 14v8" />
      <path d="M9 18h6" />
      <path d="M8 22h8" />
    </svg>
    
    {#if isLoading}
      {#if mode === 'signin'}
        Verifying...
      {:else if mode === 'signup'}
        Setting up...
      {:else}
        Adding passkey...
      {/if}
    {:else}
      {label || defaultLabel}
    {/if}
  </button>
  
  {#if error}
    <p class="vault-webauthn-error">{error.message}</p>
  {/if}
{:else}
  <div class="vault-webauthn-unsupported">
    Passkeys are not supported in this browser
  </div>
{/if}

<style>
  .vault-webauthn-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
    width: 100%;
    padding: 0.625rem 1rem;
    background: white;
    border: 1px solid #e5e7eb;
    border-radius: 0.375rem;
    font-size: 0.875rem;
    font-weight: 500;
    color: #374151;
    cursor: pointer;
    transition: all 0.15s;
  }
  
  .vault-webauthn-btn:hover:not(:disabled) {
    background: #f9fafb;
    border-color: #d1d5db;
  }
  
  .vault-webauthn-btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  
  .vault-webauthn-icon {
    width: 1.25rem;
    height: 1.25rem;
  }
  
  .vault-webauthn-error {
    margin-top: 0.5rem;
    font-size: 0.875rem;
    color: #dc2626;
  }
  
  .vault-webauthn-unsupported {
    padding: 0.75rem;
    background: #f3f4f6;
    border-radius: 0.375rem;
    font-size: 0.875rem;
    color: #6b7280;
    text-align: center;
  }
</style>
