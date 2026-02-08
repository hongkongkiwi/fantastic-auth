/**
 * Vault Vue 3 SDK
 *
 * A comprehensive Vue 3 SDK for Vault authentication and user management.
 * Built with the Composition API for maximum flexibility and reactivity.
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
 *     tenantId: 'my-tenant'
 *   }
 * });
 *
 * const app = createApp(App);
 * app.use(vault);
 * app.mount('#app');
 * ```
 *
 * @example
 * ```vue
 * <!-- App.vue -->
 * <script setup lang="ts">
 * import { useAuth, useUser } from '@vault/vue';
 *
 * const { isSignedIn, signOut } = useAuth();
 * const { user } = useUser();
 * </script>
 *
 * <template>
 *   <div v-if="isSignedIn">
 *     <p>Welcome {{ user?.name }}</p>
 *     <button @click="signOut">Sign Out</button>
 *   </div>
 *   <div v-else>
 *     <VaultSignIn />
 *   </div>
 * </template>
 * ```
 */

// ============================================================================
// Plugin & Provider
// ============================================================================

export {
  createVault,
  useVault,
  VaultInjectionKey,
} from './plugin';

export type {
  VaultPluginOptions,
  VaultContextValue,
} from './types';

// ============================================================================
// Composables
// ============================================================================

export {
  // Auth composables
  useAuth,
  useAuthState,
  useHasRole,
  useRequireAuth,

  // User composables
  useUser,
  useUpdateUser,
  useUserManager,

  // Session composables
  useSession,
  useToken,
  useSessionId,

  // Sign in/up composables
  useSignIn,
  useSignUp,

  // WebAuthn composables
  useWebAuthn,
  useIsWebAuthnSupported,

  // MFA composables
  useMfa,
  useIsMfaEnabled,
  useMfaMethods,

  // Organization composables
  useOrganization,
  useActiveOrganization,
  useOrganizationList,
  useOrganizationRole,
  useIsOrgAdmin,
  useIsOrgOwner,
  useCurrentOrgRole,

  // Permission composables
  usePermissions,
  useCheckAuthorization,

  // Session management composables
  useSessions,
} from './composables';

// ============================================================================
// API Client
// ============================================================================

export {
  VaultApiClient,
  createVaultClient,
} from './api';

// ============================================================================
// Types
// ============================================================================

export type {
  // Core types
  User,
  UserProfile,
  Session,
  SessionInfo,

  // Organization types
  Organization,
  OrganizationMember,
  OrganizationRole,
  CreateOrganizationOptions,
  InviteMemberOptions,
  UpdateOrganizationOptions,

  // Permission types
  Permission,
  PermissionCheck,

  // Config types
  VaultConfig,
  Appearance,

  // Auth option types
  SignInOptions,
  SignUpOptions,
  MagicLinkOptions,
  OAuthOptions,
  ForgotPasswordOptions,
  ResetPasswordOptions,
  VerifyEmailOptions,

  // MFA types
  MfaMethod,
  MfaChallenge,
  MfaSetupOptions,
  MfaVerifyOptions,
  TotpSetup,

  // WebAuthn types
  WebAuthnOptions,
  WebAuthnCredential,

  // Error types
  ApiError,
  AuthState,

  // Composable return types
  UseAuthReturn,
  UseSignInReturn,
  UseSignUpReturn,
  UseSessionReturn,
  UseUserReturn,
  UseWebAuthnReturn,
  UseMfaReturn,
  UseOrganizationReturn,
  UsePermissionsReturn,
  UseSessionsReturn,

  // Component prop types
  SignInProps,
  SignUpProps,
  UserButtonProps,
  UserProfileProps,
  ProtectProps,
  WebAuthnButtonProps,
  OrganizationSwitcherProps,
} from './types';

// ============================================================================
// Version
// ============================================================================

export const VERSION = '0.1.0';
