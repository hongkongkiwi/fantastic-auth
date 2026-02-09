/**
 * Vault Svelte SDK
 * 
 * A comprehensive Svelte SDK for Vault authentication and user management.
 * Supports both Svelte 4 (stores) and Svelte 5 (runes).
 * 
 * @example
 * ```svelte
 * <!-- +layout.svelte -->
 * <script>
 *   import { VaultProvider } from '@fantasticauth/svelte';
 * </script>
 * 
 * <VaultProvider config={{ apiUrl: "https://api.vault.dev", tenantId: "my-tenant" }}>
 *   <slot />
 * </VaultProvider>
 * ```
 * 
 * @example
 * ```svelte
 * <!-- +page.svelte -->
 * <script>
 *   // Svelte 5 - Runes
 *   import { useAuth } from '@fantasticauth/svelte';
 *   const { isSignedIn, user, signOut } = useAuth();
 * </script>
 * 
 * {#if isSignedIn}
 *   <p>Welcome {user?.email}</p>
 *   <button onclick={signOut}>Sign Out</button>
 * {:else}
 *   <SignIn />
 * {/if}
 * ```
 */

// ============================================================================
// Provider & Context
// ============================================================================

export { default as VaultProvider } from './VaultProvider.svelte';
export { getVaultContext, hasVaultContext, VAULT_CONTEXT_KEY } from './context.js';
export { default as FantasticauthProvider } from './VaultProvider.svelte';
export {
  getVaultContext as getFantasticauthContext,
  hasVaultContext as hasFantasticauthContext,
  VAULT_CONTEXT_KEY as FANTASTICAUTH_CONTEXT_KEY,
} from './context.js';

// ============================================================================
// Components
// ============================================================================

export {
  // Auth Components
  SignIn,
  SignUp,
  UserButton,
  UserProfile,
  WebAuthnButton,
  
  // Organization Components
  OrganizationSwitcher,
  
  // Control Components
  SignedIn,
  SignedOut,
  Protect,
} from './components/index.js';

// ============================================================================
// Stores (Svelte 4) & Runes (Svelte 5)
// ============================================================================

export {
  // Svelte 4 - Stores
  authStore,
  userStore,
  sessionStore,
  organizationStore,
  
  // Svelte 5 - Runes
  useAuth,
  useSignIn,
  useSignUp,
  useAuthState,
  useRequireAuth,
} from './stores/index.js';

export { useUser, useUpdateUser } from './stores/user.js';
export { useOrganization, useOrganizationRole, useOrganizationMembers } from './stores/organization.js';
export { useSession, useSessions } from './stores/session.js';

// ============================================================================
// Actions
// ============================================================================

export { protect, type ProtectActionOptions } from './actions/index.js';

// ============================================================================
// API Client
// ============================================================================

export {
  VaultApiClientImpl,
  createVaultClient,
  VaultApiClientImpl as FantasticauthApiClient,
  createVaultClient as createFantasticauthClient,
} from './api.js';

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
  
  // Component props
  SignInProps,
  SignUpProps,
  UserButtonProps,
  UserProfileProps,
  ProtectProps,
  WebAuthnButtonProps,
  OrganizationSwitcherProps,
  
  // Hook return types
  UseAuthReturn,
  UseSignInReturn,
  UseSignUpReturn,
  UseUserReturn,
  UseSessionReturn,
  UseOrganizationReturn,
  UseMfaReturn,
  UseWebAuthnReturn,
  
  // Context types
  VaultContextValue,
  VaultProviderProps,
  VaultApiClient,
  VaultContextValue as FantasticauthContextValue,
  VaultProviderProps as FantasticauthProviderProps,
  VaultApiClient as FantasticauthApiClientType,
  
  // SvelteKit server types
  VaultAuthConfig,
  VaultLocals,
  VaultAuthConfig as FantasticauthAuthConfig,
  VaultLocals as FantasticauthLocals,
} from './types.js';

// ============================================================================
// Version
// ============================================================================

export const VERSION = '0.1.0';
