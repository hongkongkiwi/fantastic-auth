/**
 * Auth Stores
 * 
 * Svelte stores and Svelte 5 runes for authentication state.
 */

import { getVaultContext } from '../context.js';
import type { 
  SignInOptions, 
  MagicLinkOptions, 
  OAuthOptions, 
  SignUpOptions,
  ApiError 
} from '../types.js';

// ============================================================================
// Svelte 4 - Readable Stores (derived from context)
// ============================================================================

/**
 * Auth store - provides authentication state
 * Compatible with Svelte 4 stores pattern ($authStore)
 * 
 * @example
 * ```svelte
 * <script>
 *   import { authStore } from '@fantasticauth/svelte';
 * </script>
 * 
 * {#if $authStore.isSignedIn}
 *   <p>Welcome!</p>
 * {:else if $authStore.isLoaded}
 *   <SignIn />
 * {:else}
 *   <Loading />
 * {/if}
 * ```
 */
export function authStore() {
  const vault = getVaultContext();
  return {
    subscribe: vault.isSignedIn.subscribe,
    isLoaded: vault.isLoaded,
    isSignedIn: vault.isSignedIn,
    authState: vault.authState
  };
}

/**
 * User store - provides current user state
 * 
 * @example
 * ```svelte
 * <script>
 *   import { userStore } from '@fantasticauth/svelte';
 * </script>
 * 
 * <p>Welcome {$userStore.user?.name}</p>
 * ```
 */
export function userStore() {
  const vault = getVaultContext();
  return {
    subscribe: vault.user.subscribe,
    user: vault.user,
    update: vault.updateUser,
    reload: vault.reloadUser
  };
}

/**
 * Session store - provides session state
 * 
 * @example
 * ```svelte
 * <script>
 *   import { sessionStore } from '@fantasticauth/svelte';
 * </script>
 * 
 * <p>Session expires at: {$sessionStore.session?.expiresAt}</p>
 * ```
 */
export function sessionStore() {
  const vault = getVaultContext();
  return {
    subscribe: vault.session.subscribe,
    session: vault.session,
    getToken: vault.getToken,
    refresh: vault.refreshSession
  };
}

/**
 * Organization store - provides organization state
 * 
 * @example
 * ```svelte
 * <script>
 *   import { organizationStore } from '@fantasticauth/svelte';
 * </script>
 * 
 * {#each $organizationStore.organizations as org}
 *   <p>{org.name}</p>
 * {/each}
 * ```
 */
export function organizationStore() {
  const vault = getVaultContext();
  return {
    subscribe: vault.organizations.subscribe,
    organization: vault.organization,
    organizations: vault.organizations,
    setActive: vault.setActiveOrganization,
    create: vault.createOrganization,
    leave: vault.leaveOrganization,
    refresh: vault.refreshOrganizations
  };
}

// ============================================================================
// Svelte 5 - Runes
// ============================================================================

/**
 * useAuth - Svelte 5 rune for authentication state and actions
 * 
 * @example
 * ```svelte
 * <script>
 *   import { useAuth } from '@fantasticauth/svelte';
 *   const { isSignedIn, user, signOut } = useAuth();
 * </script>
 * 
 * {#if isSignedIn}
 *   <p>Welcome {user?.email}</p>
 *   <button onclick={signOut}>Sign Out</button>
 * {/if}
 * ```
 */
export function useAuth() {
  const vault = getVaultContext();
  
  return {
    // State (reactive runes)
    get isLoaded() {
      // Access the store value reactively
      let value = $state(false);
      vault.isLoaded.subscribe(v => value = v)();
      return value;
    },
    get isSignedIn() {
      let value = $state(false);
      vault.isSignedIn.subscribe(v => value = v)();
      return value;
    },
    get user() {
      let value = $state<ReturnType<typeof vault.user.subscribe> extends { subscribe(fn: (v: infer V) => void): () => void } ? V : never | null>(null);
      vault.user.subscribe(v => value = v)();
      return value;
    },
    get session() {
      let value = $state<ReturnType<typeof vault.session.subscribe> extends { subscribe(fn: (v: infer V) => void): () => void } ? V : never | null>(null);
      vault.session.subscribe(v => value = v)();
      return value;
    },
    get organization() {
      let value = $state<ReturnType<typeof vault.organization.subscribe> extends { subscribe(fn: (v: infer V) => void): () => void } ? V : never | null>(null);
      vault.organization.subscribe(v => value = v)();
      return value;
    },
    
    // Actions
    signIn: vault.signIn,
    signInWithMagicLink: vault.signInWithMagicLink,
    signInWithOAuth: vault.signInWithOAuth,
    signUp: vault.signUp,
    signOut: vault.signOut,
  };
}

/**
 * useSignIn - Svelte 5 rune for sign-in operations with loading state
 * 
 * @example
 * ```svelte
 * <script>
 *   import { useSignIn } from '@fantasticauth/svelte';
 *   const { signIn, isLoading, error } = useSignIn();
 *   
 *   let email = $state('');
 *   let password = $state('');
 * </script>
 * 
 * <form onsubmit={() => signIn({ email, password })}>
 *   <input bind:value={email} type="email" />
 *   <input bind:value={password} type="password" />
 *   <button disabled={isLoading}>Sign In</button>
 * </form>
 * {#if error}
 *   <p>{error.message}</p>
 * {/if}
 * ```
 */
export function useSignIn() {
  const vault = getVaultContext();
  
  let isLoading = $state(false);
  let error = $state<ApiError | null>(null);
  
  async function signIn(options: SignInOptions): Promise<void> {
    isLoading = true;
    error = null;
    try {
      await vault.signIn(options);
    } catch (e) {
      error = e as ApiError;
      throw e;
    } finally {
      isLoading = false;
    }
  }
  
  async function signInWithMagicLink(options: MagicLinkOptions): Promise<void> {
    isLoading = true;
    error = null;
    try {
      await vault.signInWithMagicLink(options);
    } catch (e) {
      error = e as ApiError;
      throw e;
    } finally {
      isLoading = false;
    }
  }
  
  async function signInWithOAuth(options: OAuthOptions): Promise<void> {
    isLoading = true;
    error = null;
    try {
      await vault.signInWithOAuth(options);
    } catch (e) {
      error = e as ApiError;
      throw e;
    } finally {
      isLoading = false;
    }
  }
  
  function resetError(): void {
    error = null;
    vault.clearError();
  }
  
  return {
    get isLoading() { return isLoading; },
    get error() { return error; },
    signIn,
    signInWithMagicLink,
    signInWithOAuth,
    resetError,
  };
}

/**
 * useSignUp - Svelte 5 rune for sign-up operations with loading state
 */
export function useSignUp() {
  const vault = getVaultContext();
  
  let isLoading = $state(false);
  let error = $state<ApiError | null>(null);
  
  async function signUp(options: SignUpOptions): Promise<void> {
    isLoading = true;
    error = null;
    try {
      await vault.signUp(options);
    } catch (e) {
      error = e as ApiError;
      throw e;
    } finally {
      isLoading = false;
    }
  }
  
  async function signUpWithOAuth(options: OAuthOptions): Promise<void> {
    isLoading = true;
    error = null;
    try {
      // Use signInWithOAuth as it handles OAuth flow
      await vault.signInWithOAuth(options);
    } catch (e) {
      error = e as ApiError;
      throw e;
    } finally {
      isLoading = false;
    }
  }
  
  function resetError(): void {
    error = null;
    vault.clearError();
  }
  
  return {
    get isLoading() { return isLoading; },
    get error() { return error; },
    signUp,
    signUpWithOAuth,
    resetError,
  };
}

/**
 * useAuthState - Get simple auth state (lighter than useAuth)
 * 
 * @example
 * ```svelte
 * <script>
 *   import { useAuthState } from '@fantasticauth/svelte';
 *   const { isSignedIn, isLoaded } = useAuthState();
 * </script>
 * 
 * {#if isLoaded}
 *   {#if isSignedIn}
 *     <Dashboard />
 *   {:else}
 *     <SignIn />
 *   {/if}
 * {:else}
 *   <Loading />
 * {/if}
 * ```
 */
export function useAuthState(): { isLoaded: boolean; isSignedIn: boolean } {
  const vault = getVaultContext();
  
  return {
    get isLoaded() {
      let value = $state(false);
      vault.isLoaded.subscribe(v => value = v)();
      return value;
    },
    get isSignedIn() {
      let value = $state(false);
      vault.isSignedIn.subscribe(v => value = v)();
      return value;
    },
  };
}

/**
 * useRequireAuth - Require authentication, throws if not authenticated
 * 
 * @example
 * ```svelte
 * <script>
 *   import { useRequireAuth } from '@fantasticauth/svelte';
 *   
 *   // This will throw if not authenticated
 *   const { user, session } = useRequireAuth();
 * </script>
 * 
 * <h1>Welcome {user.name}</h1>
 * ```
 */
export function useRequireAuth() {
  const vault = getVaultContext();
  
  const isSignedIn = $derived.by(() => {
    let value = false;
    vault.isSignedIn.subscribe(v => value = v)();
    return value;
  });
  
  const user = $derived.by(() => {
    let value = null;
    vault.user.subscribe(v => value = v)();
    return value;
  });
  
  const session = $derived.by(() => {
    let value = null;
    vault.session.subscribe(v => value = v)();
    return value;
  });
  
  const organization = $derived.by(() => {
    let value = null;
    vault.organization.subscribe(v => value = v)();
    return value;
  });
  
  if (!isSignedIn || !user || !session) {
    throw new Error('Authentication required');
  }
  
  return { user, session, organization };
}
