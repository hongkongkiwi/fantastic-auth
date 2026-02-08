/**
 * Vault Vue Plugin
 *
 * Vue plugin for Vault authentication with global state management.
 */

import {
  ref,
  computed,
  provide,
  inject,
  onMounted,
  readonly,
} from 'vue';
import type { App, InjectionKey, Ref } from 'vue';
import { VaultApiClient } from './api/client';
import type {
  VaultConfig,
  VaultPluginOptions,
  VaultContextValue,
  User,
  Session,
  Organization,
  SessionInfo,
  AuthState,
  ApiError,
  MfaChallenge,
  MfaMethod,
  TotpSetup,
  SignInOptions,
  SignUpOptions,
  MagicLinkOptions,
  OAuthOptions,
  ForgotPasswordOptions,
  ResetPasswordOptions,
  VerifyEmailOptions,
} from './types';
import { VaultInjectionKey } from './types';

// Re-export the injection key
export { VaultInjectionKey };

/**
 * Create the Vault plugin instance
 *
 * @param options - Plugin configuration options
 * @returns Vue plugin object
 *
 * @example
 * ```ts
 * // main.ts
 * import { createApp } from 'vue';
 * import { createVault } from '@vault/vue';
 * import App from './App.vue';
 *
 * const vault = createVault({
 *   config: {
 *     apiUrl: 'https://api.vault.dev',
 *     tenantId: 'my-tenant',
 *   }
 * });
 *
 * const app = createApp(App);
 * app.use(vault);
 * app.mount('#app');
 * ```
 */
export function createVault(options: VaultPluginOptions) {
  const { config, initialUser, initialSessionToken, onAuthStateChange, appearance } = options;

  return {
    install(app: App) {
      // Create reactive state
      const authState = ref<AuthState>(
        initialUser
          ? { status: 'authenticated', user: initialUser, session: {} as Session }
          : { status: 'loading' }
      );

      const organizations = ref<Organization[]>([]);
      const activeOrg = ref<Organization | null>(null);
      const sessions = ref<SessionInfo[]>([]);
      const mfaChallenge = ref<MfaChallenge | null>(null);
      const lastError = ref<ApiError | null>(null);

      // Create API client
      const api = new VaultApiClient({
        ...config,
        sessionToken: initialSessionToken,
      });

      // Computed state
      const isLoaded = computed(() => authState.value.status !== 'loading');
      const isSignedIn = computed(() => authState.value.status === 'authenticated');
      const user = computed<User | null>(() =>
        authState.value.status === 'authenticated' ? authState.value.user : null
      );
      const session = computed<Session | null>(() =>
        authState.value.status === 'authenticated' ? authState.value.session : null
      );
      const organization = computed(() => activeOrg.value);

      // Notify auth state changes
      if (onAuthStateChange) {
        watch(
          () => authState.value,
          (newState) => {
            onAuthStateChange(newState);
          },
          { deep: true }
        );
      }

      // ============================================================================
      // Auth Methods
      // ============================================================================

      const signIn = async (options: SignInOptions) => {
        try {
          authState.value = { status: 'loading' };
          lastError.value = null;

          const response = await api.signIn(options);

          if (response.mfaRequired) {
            mfaChallenge.value = response.mfaChallenge as MfaChallenge;
            authState.value = {
              status: 'mfa_required',
              challenge: response.mfaChallenge as MfaChallenge,
            };
          } else {
            await api.storeToken(response.session.accessToken);
            if (response.session.refreshToken) {
              await api.storeRefreshToken(response.session.refreshToken);
            }
            authState.value = {
              status: 'authenticated',
              user: response.user,
              session: response.session,
            };
            await refreshOrganizations();
          }
        } catch (error) {
          const apiError = error as ApiError;
          lastError.value = apiError;
          authState.value = {
            status: 'error',
            error: apiError,
          };
          throw error;
        }
      };

      const signInWithMagicLink = async (options: MagicLinkOptions) => {
        lastError.value = null;
        await api.sendMagicLink(options);
      };

      const signInWithOAuth = async (options: OAuthOptions) => {
        lastError.value = null;
        const { url } = await api.getOAuthUrl(options);
        window.location.href = url;
      };

      const signUp = async (options: SignUpOptions) => {
        try {
          authState.value = { status: 'loading' };
          lastError.value = null;

          const response = await api.signUp(options);

          await api.storeToken(response.session.accessToken);
          if (response.session.refreshToken) {
            await api.storeRefreshToken(response.session.refreshToken);
          }
          authState.value = {
            status: 'authenticated',
            user: response.user,
            session: response.session,
          };
          await refreshOrganizations();
        } catch (error) {
          const apiError = error as ApiError;
          lastError.value = apiError;
          authState.value = {
            status: 'error',
            error: apiError,
          };
          throw error;
        }
      };

      const signOut = async () => {
        try {
          await api.signOut();
        } finally {
          await api.clearToken();
          authState.value = { status: 'unauthenticated' };
          activeOrg.value = null;
          organizations.value = [];
          mfaChallenge.value = null;
        }
      };

      // ============================================================================
      // Password Reset Methods
      // ============================================================================

      const sendForgotPassword = async (options: ForgotPasswordOptions) => {
        lastError.value = null;
        await api.sendForgotPassword(options);
      };

      const resetPassword = async (options: ResetPasswordOptions) => {
        try {
          lastError.value = null;
          const response = await api.resetPassword(options);

          await api.storeToken(response.session.accessToken);
          if (response.session.refreshToken) {
            await api.storeRefreshToken(response.session.refreshToken);
          }
          authState.value = {
            status: 'authenticated',
            user: response.user,
            session: response.session,
          };
          await refreshOrganizations();

          return response;
        } catch (error) {
          lastError.value = error as ApiError;
          throw error;
        }
      };

      // ============================================================================
      // Email Verification Methods
      // ============================================================================

      const verifyEmail = async (options: VerifyEmailOptions) => {
        try {
          lastError.value = null;
          const { user: verifiedUser } = await api.verifyEmail(options);

          if (authState.value.status === 'authenticated') {
            authState.value = {
              ...authState.value,
              user: { ...authState.value.user, ...verifiedUser },
            };
          }
        } catch (error) {
          lastError.value = error as ApiError;
          throw error;
        }
      };

      const resendVerificationEmail = async () => {
        lastError.value = null;
        await api.resendVerificationEmail();
      };

      // ============================================================================
      // MFA Methods
      // ============================================================================

      const verifyMfa = async (code: string, method: MfaMethod) => {
        try {
          lastError.value = null;
          const response = await api.verifyMfa(code, method);

          await api.storeToken(response.session.accessToken);
          if (response.session.refreshToken) {
            await api.storeRefreshToken(response.session.refreshToken);
          }
          mfaChallenge.value = null;
          authState.value = {
            status: 'authenticated',
            user: response.user,
            session: response.session,
          };
          await refreshOrganizations();
        } catch (error) {
          lastError.value = error as ApiError;
          throw error;
        }
      };

      const setupTotp = async (): Promise<TotpSetup | null> => {
        try {
          lastError.value = null;
          return await api.setupTotp();
        } catch (error) {
          lastError.value = error as ApiError;
          throw error;
        }
      };

      const verifyTotpSetup = async (code: string) => {
        try {
          lastError.value = null;
          await api.verifyTotpSetup(code);
          await reloadUser();
        } catch (error) {
          lastError.value = error as ApiError;
          throw error;
        }
      };

      const disableMfa = async (method: MfaMethod) => {
        try {
          lastError.value = null;
          await api.disableMfa(method);
          await reloadUser();
        } catch (error) {
          lastError.value = error as ApiError;
          throw error;
        }
      };

      const generateBackupCodes = async (): Promise<string[]> => {
        try {
          lastError.value = null;
          const { codes } = await api.generateBackupCodes();
          return codes;
        } catch (error) {
          lastError.value = error as ApiError;
          throw error;
        }
      };

      // ============================================================================
      // User Methods
      // ============================================================================

      const updateUser = async (updates: Partial<User>) => {
        try {
          lastError.value = null;
          const updated = await api.updateUser(updates);

          if (authState.value.status === 'authenticated') {
            authState.value = {
              ...authState.value,
              user: { ...authState.value.user, ...updated },
            };
          }
        } catch (error) {
          lastError.value = error as ApiError;
          throw error;
        }
      };

      const reloadUser = async () => {
        try {
          lastError.value = null;
          const loadedUser = await api.getCurrentUser();

          if (authState.value.status === 'authenticated') {
            authState.value = {
              ...authState.value,
              user: loadedUser,
            };
          }
        } catch (error) {
          lastError.value = error as ApiError;
          throw error;
        }
      };

      const changePassword = async (currentPassword: string, newPassword: string) => {
        try {
          lastError.value = null;
          await api.changePassword(currentPassword, newPassword);
        } catch (error) {
          lastError.value = error as ApiError;
          throw error;
        }
      };

      const deleteUser = async () => {
        try {
          lastError.value = null;
          await api.deleteUser();
          await api.clearToken();
          authState.value = { status: 'unauthenticated' };
          activeOrg.value = null;
          organizations.value = [];
        } catch (error) {
          lastError.value = error as ApiError;
          throw error;
        }
      };

      // ============================================================================
      // Organization Methods
      // ============================================================================

      const refreshOrganizations = async () => {
        try {
          const orgs = await api.listOrganizations();
          organizations.value = orgs;
        } catch (error) {
          // Silently fail - not critical
          if (config.debug) {
            console.error('[Vault SDK] Failed to load organizations:', error);
          }
        }
      };

      const setActiveOrganization = async (orgId: string | null) => {
        try {
          lastError.value = null;

          // Call API to switch organization context in the token
          const response = await api.setActiveOrganization(orgId);

          // Update token with new org context
          await api.storeToken(response.session.accessToken);
          if (response.session.refreshToken) {
            await api.storeRefreshToken(response.session.refreshToken);
          }

          // Update auth state with new user and session
          if (authState.value.status === 'authenticated') {
            authState.value = {
              ...authState.value,
              user: response.user,
              session: { ...authState.value.session, ...response.session },
            };
          }

          // Update active organization
          if (orgId === null) {
            activeOrg.value = null;
          } else {
            const org = organizations.value.find((o) => o.id === orgId);
            if (org) {
              activeOrg.value = org;
            }
          }
        } catch (error) {
          lastError.value = error as ApiError;
          throw error;
        }
      };

      const createOrganization = async (name: string, slug?: string) => {
        try {
          lastError.value = null;
          const org = await api.createOrganization({ name, slug });
          organizations.value = [...organizations.value, org];
          activeOrg.value = org;
          return org;
        } catch (error) {
          lastError.value = error as ApiError;
          throw error;
        }
      };

      const leaveOrganization = async (orgId: string) => {
        try {
          lastError.value = null;
          await api.leaveOrganization(orgId);
          organizations.value = organizations.value.filter((o) => o.id !== orgId);
          if (activeOrg.value?.id === orgId) {
            activeOrg.value = null;
          }
        } catch (error) {
          lastError.value = error as ApiError;
          throw error;
        }
      };

      // ============================================================================
      // Session Methods
      // ============================================================================

      const getToken = async () => {
        return api.getStoredToken();
      };

      const refreshSession = async () => {
        try {
          const { session: newSession } = await api.refreshSession();
          await api.storeToken(newSession.accessToken);

          if (authState.value.status === 'authenticated') {
            authState.value = {
              ...authState.value,
              session: { ...authState.value.session, ...newSession },
            };
          }
        } catch (error) {
          // Clear session on refresh failure
          await api.clearToken();
          authState.value = { status: 'unauthenticated' };
          throw error;
        }
      };

      // ============================================================================
      // Error Handling
      // ============================================================================

      const clearError = () => {
        lastError.value = null;
        if (authState.value.status === 'error') {
          authState.value = { status: 'unauthenticated' };
        }
      };

      // ============================================================================
      // Initialization
      // ============================================================================

      onMounted(async () => {
        // Skip if we have initial user (SSR)
        if (initialUser) {
          await refreshOrganizations();
          return;
        }

        try {
          const token = await api.getStoredToken();

          if (token) {
            // Validate token and get user
            const session = await api.validateSession(token);
            authState.value = {
              status: 'authenticated',
              user: session.user,
              session,
            };

            // Store refresh token if provided
            if (session.refreshToken) {
              await api.storeRefreshToken(session.refreshToken);
            }

            // Load organizations
            await refreshOrganizations();
          } else {
            authState.value = { status: 'unauthenticated' };
          }
        } catch (error) {
          // Clear invalid token
          await api.clearToken();
          authState.value = { status: 'unauthenticated' };
        }
      });

      // ============================================================================
      // Context Value
      // ============================================================================

      const vaultContext: VaultContextValue = {
        // State
        isLoaded,
        isSignedIn,
        user: readonly(user) as Ref<User | null>,
        session: readonly(session) as Ref<Session | null>,
        organization: readonly(organization) as Ref<Organization | null>,
        organizations: readonly(organizations) as Ref<Organization[]>,
        authState: readonly(authState) as Ref<AuthState>,
        mfaChallenge: readonly(mfaChallenge) as Ref<MfaChallenge | null>,
        lastError: readonly(lastError) as Ref<ApiError | null>,

        // Auth methods
        signIn,
        signInWithMagicLink,
        signInWithOAuth,
        signUp,
        signOut,

        // Password reset
        sendForgotPassword,
        resetPassword,

        // Email verification
        verifyEmail,
        resendVerificationEmail,

        // MFA
        verifyMfa,
        setupTotp,
        verifyTotpSetup,
        disableMfa,
        generateBackupCodes,

        // User methods
        updateUser,
        reloadUser,
        changePassword,
        deleteUser,

        // Organization methods
        setActiveOrganization,
        createOrganization,
        leaveOrganization,
        refreshOrganizations,

        // Session methods
        getToken,
        refreshSession,

        // Error handling
        clearError,
      };

      // Provide the context to all child components
      app.provide(VaultInjectionKey, vaultContext);

      // Also provide a global property for options API users
      app.config.globalProperties.$vault = vaultContext;
    },
  };
}

/**
 * Inject the Vault context into a component
 *
 * @returns The Vault context value
 * @throws Error if used outside of VaultProvider
 *
 * @example
 * ```vue
 * <script setup lang="ts">
 * import { useVault } from '@vault/vue';
 *
 * const vault = useVault();
 * console.log(vault.user.value?.email);
 * </script>
 * ```
 */
export function useVault(): VaultContextValue {
  const context = inject(VaultInjectionKey);

  if (!context) {
    throw new Error('useVault must be used within a VaultProvider. Make sure to install the Vault plugin with app.use(vault).');
  }

  return context;
}

// Import watch for auth state changes
import { watch } from 'vue';

// Extend Vue module for TypeScript support
declare module '@vue/runtime-core' {
  export interface ComponentCustomProperties {
    $vault: VaultContextValue;
  }
}
