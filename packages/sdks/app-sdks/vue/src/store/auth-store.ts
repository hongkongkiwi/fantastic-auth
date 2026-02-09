/**
 * Pinia Auth Store
 *
 * Pinia store for Vault authentication state.
 * Provides an alternative to the composables for state management.
 *
 * @example
 * ```ts
 * // store/index.ts
 * import { createPinia } from 'pinia';
 * import { useAuthStore } from '@fantasticauth/vue/store';
 *
 * const pinia = createPinia();
 * export { useAuthStore };
 * ```
 *
 * @example
 * ```vue
 * <script setup lang="ts">
 * import { useAuthStore } from '@fantasticauth/vue/store';
 *
 * const auth = useAuthStore();
 * </script>
 *
 * <template>
 *   <div v-if="auth.isSignedIn">
 *     <p>Welcome {{ auth.user?.name }}</p>
 *     <button @click="auth.signOut">Sign Out</button>
 *   </div>
 * </template>
 * ```
 */

import { ref, computed } from 'vue';
import type { Ref } from 'vue';
import { defineStore } from 'pinia';
import type {
  User,
  Session,
  Organization,
  AuthState,
  ApiError,
  SignInOptions,
  SignUpOptions,
  MagicLinkOptions,
  OAuthOptions,
} from '../types';

/**
 * Auth store definition
 * Note: This is a type-only definition. The actual store needs to be
 * created with access to the Vault context, which requires the plugin
 * to be installed first.
 *
 * For full functionality, use the composables or create a custom store
 * that imports from the Vault context.
 */
export interface AuthStoreState {
  // State
  authState: Ref<AuthState>;
  organizations: Ref<Organization[]>;
  activeOrg: Ref<Organization | null>;
  lastError: Ref<ApiError | null>;

  // Getters
  isLoaded: Ref<boolean>;
  isSignedIn: Ref<boolean>;
  user: Ref<User | null>;
  session: Ref<Session | null>;
  organization: Ref<Organization | null>;

  // Actions
  signIn: (options: SignInOptions) => Promise<void>;
  signInWithMagicLink: (options: MagicLinkOptions) => Promise<void>;
  signInWithOAuth: (options: OAuthOptions) => Promise<void>;
  signUp: (options: SignUpOptions) => Promise<void>;
  signOut: () => Promise<void>;
  setActiveOrganization: (orgId: string | null) => Promise<void>;
  refreshOrganizations: () => Promise<void>;
}

/**
 * Create a Pinia store that wraps the Vault context
 * This should be called after the Vault plugin is installed
 *
 * @param vault - The Vault context from useVault()
 * @returns Pinia store
 */
export function createAuthStore(vault: any) {
  return defineStore('vaultAuth', () => {
    // State - use vault's reactive refs
    const authState = vault.authState;
    const organizations = vault.organizations;
    const activeOrg = vault.organization;
    const lastError = vault.lastError;

    // Getters
    const isLoaded = vault.isLoaded;
    const isSignedIn = vault.isSignedIn;
    const user = vault.user;
    const session = vault.session;
    const organization = vault.organization;

    // Actions - wrap vault methods
    const signIn = vault.signIn;
    const signInWithMagicLink = vault.signInWithMagicLink;
    const signInWithOAuth = vault.signInWithOAuth;
    const signUp = vault.signUp;
    const signOut = vault.signOut;
    const setActiveOrganization = vault.setActiveOrganization;
    const refreshOrganizations = vault.refreshOrganizations;

    return {
      // State
      authState,
      organizations,
      activeOrg,
      lastError,

      // Getters
      isLoaded,
      isSignedIn,
      user,
      session,
      organization,

      // Actions
      signIn,
      signInWithMagicLink,
      signInWithOAuth,
      signUp,
      signOut,
      setActiveOrganization,
      refreshOrganizations,
    };
  });
}

/**
 * Example of using the store pattern with Vault
 *
 * ```ts
 * // stores/auth.ts
 * import { defineStore } from 'pinia';
 * import { useVault } from '@fantasticauth/vue';
 *
 * export const useAuthStore = defineStore('auth', () => {
 *   const vault = useVault();
 *
 *   // Re-export vault state and methods
 *   return {
 *     isLoaded: vault.isLoaded,
 *     isSignedIn: vault.isSignedIn,
 *     user: vault.user,
 *     session: vault.session,
 *     organization: vault.organization,
 *     organizations: vault.organizations,
 *     signIn: vault.signIn,
 *     signOut: vault.signOut,
 *     // ... etc
 *   };
 * });
 * ```
 */
