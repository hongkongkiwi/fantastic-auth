/**
 * useAuth Composable
 *
 * Primary composable for authentication state and actions.
 *
 * @example
 * ```vue
 * <script setup lang="ts">
 * import { useAuth } from '@vault/vue';
 *
 * const { isSignedIn, user, signOut } = useAuth();
 * </script>
 *
 * <template>
 *   <div v-if="isSignedIn">
 *     <p>Hello {{ user?.email }}</p>
 *     <button @click="signOut">Sign out</button>
 *   </div>
 * </template>
 * ```
 */

import { computed, toValue } from 'vue';
import type { Ref, MaybeRefOrGetter } from 'vue';
import { useVault } from '../plugin';
import type {
  SignInOptions,
  MagicLinkOptions,
  OAuthOptions,
  SignUpOptions,
  UseAuthReturn,
  User,
  Session,
  Organization,
} from '../types';

/**
 * Composable to access authentication state and methods.
 * Must be used within a VaultProvider.
 *
 * @returns Authentication state and methods
 */
export function useAuth(): UseAuthReturn {
  const vault = useVault();

  return {
    // State - return the refs directly for Vue reactivity
    isLoaded: vault.isLoaded,
    isSignedIn: vault.isSignedIn,
    user: vault.user,
    session: vault.session,
    organization: vault.organization,

    // Actions
    signIn: vault.signIn,
    signInWithMagicLink: vault.signInWithMagicLink,
    signInWithOAuth: vault.signInWithOAuth,
    signUp: vault.signUp,
    signOut: vault.signOut,
  };
}

/**
 * Composable to get the current authentication state only.
 * Useful when you only need to check if user is signed in.
 *
 * @returns Object with isLoaded and isSignedIn booleans
 */
export function useAuthState(): {
  isLoaded: Ref<boolean>;
  isSignedIn: Ref<boolean>;
} {
  const vault = useVault();

  return {
    isLoaded: vault.isLoaded,
    isSignedIn: vault.isSignedIn,
  };
}

/**
 * Composable to check if the current user has a specific role.
 *
 * @param role - The role to check for
 * @returns Boolean ref indicating if user has the role
 */
export function useHasRole(role: MaybeRefOrGetter<string>): Ref<boolean> {
  const vault = useVault();

  return computed(() => {
    if (!vault.isSignedIn.value || !vault.user.value) {
      return false;
    }

    const roleValue = toValue(role);

    // Check organization role
    if (vault.organization.value?.role === roleValue) {
      return true;
    }

    return false;
  });
}

/**
 * Composable to require authentication.
 * Returns the user or throws if not authenticated.
 *
 * @returns Object with user, session, and organization
 * @throws Error if not authenticated
 */
export function useRequireAuth(): {
  user: Ref<User>;
  session: Ref<Session>;
  organization: Ref<Organization | null>;
} {
  const vault = useVault();

  if (!vault.isSignedIn.value || !vault.user.value || !vault.session.value) {
    throw new Error('Authentication required');
  }

  return {
    user: vault.user as Ref<User>,
    session: vault.session as Ref<Session>,
    organization: vault.organization,
  };
}
