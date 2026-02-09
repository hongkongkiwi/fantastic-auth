/**
 * Vault Vue SDK Types
 *
 * TypeScript types for the Vault Vue authentication SDK.
 */

import { InjectionKey, Ref } from 'vue';

// ============================================================================
// Core User Types
// ============================================================================

export interface User {
  id: string;
  tenantId: string;
  email: string;
  emailVerified: boolean;
  status: 'pending' | 'active' | 'suspended' | 'deactivated';
  profile: UserProfile;
  mfaEnabled: boolean;
  mfaMethods: MfaMethod[];
  lastLoginAt?: string;
  createdAt: string;
  updatedAt: string;
}

export interface UserProfile {
  name?: string;
  givenName?: string;
  familyName?: string;
  picture?: string;
  phoneNumber?: string;
  [key: string]: any;
}

export type MfaMethod = 'totp' | 'email' | 'sms' | 'webauthn' | 'backup_codes';

// ============================================================================
// Session Types
// ============================================================================

export interface Session {
  id: string;
  accessToken: string;
  refreshToken: string;
  expiresAt: string;
  user: User;
}

export interface SessionInfo {
  id: string;
  userId: string;
  userAgent?: string;
  ipAddress?: string;
  location?: string;
  createdAt: string;
  lastActiveAt: string;
  expiresAt: string;
  isCurrent: boolean;
}

// ============================================================================
// Permission Types
// ============================================================================

export interface PermissionCheck {
  permission?: string;
  role?: string;
  anyRole?: string[];
}

export type Permission =
  | 'org:read'
  | 'org:write'
  | 'org:delete'
  | 'member:read'
  | 'member:write'
  | 'member:delete'
  | 'billing:read'
  | 'billing:write'
  | 'settings:read'
  | 'settings:write'
  | string;

// ============================================================================
// Organization Types
// ============================================================================

export interface Organization {
  id: string;
  tenantId: string;
  name: string;
  slug: string;
  logoUrl?: string;
  description?: string;
  website?: string;
  maxMembers?: number;
  role: OrganizationRole;
  createdAt: string;
  updatedAt: string;
}

export type OrganizationRole = 'owner' | 'admin' | 'member' | 'guest';

export interface OrganizationMember {
  id: string;
  userId: string;
  email: string;
  name?: string;
  role: OrganizationRole;
  status: 'pending' | 'active' | 'suspended';
  joinedAt?: string;
}

export interface CreateOrganizationOptions {
  name: string;
  slug?: string;
  logo?: File;
  description?: string;
}

export interface InviteMemberOptions {
  email: string;
  role: OrganizationRole;
  organizationId?: string;
}

export interface UpdateOrganizationOptions {
  name?: string;
  slug?: string;
  logo?: File;
  description?: string;
}

// ============================================================================
// Configuration Types
// ============================================================================

export interface VaultConfig {
  apiUrl: string;
  tenantId: string;
  /**
   * @deprecated Use tenantId instead
   */
  tenantSlug?: string;
  /**
   * Enable debug logging
   */
  debug?: boolean;
  /**
   * Session token (for SSR)
   */
  sessionToken?: string;
  /**
   * Custom fetch implementation
   */
  fetch?: typeof fetch;
  /**
   * Turnstile site key for bot protection
   */
  turnstileSiteKey?: string;
  /**
   * OAuth providers configuration
   */
  oauth?: {
    google?: { clientId: string };
    github?: { clientId: string };
    microsoft?: { clientId: string };
  };
  /**
   * Browser token storage mode.
   * `sessionStorage` is safer than `localStorage` and is the default.
   */
  tokenStorage?: 'memory' | 'sessionStorage' | 'localStorage';
  /**
   * Custom token storage adapter for advanced integrations.
   */
  tokenStorageAdapter?: {
    getItem: (key: string) => string | null;
    setItem: (key: string, value: string) => void;
    removeItem: (key: string) => void;
  };
}

export interface VaultPluginOptions {
  config: VaultConfig;
  /**
   * Initial user data (for SSR)
   */
  initialUser?: User;
  /**
   * Initial session token (for SSR)
   */
  initialSessionToken?: string;
  /**
   * Callback when authentication state changes
   */
  onAuthStateChange?: (state: AuthState) => void;
  /**
   * Global appearance configuration for components
   */
  appearance?: Appearance;
}

// ============================================================================
// Auth Options Types
// ============================================================================

export interface SignInOptions {
  email: string;
  password: string;
  turnstileToken?: string;
}

export interface SignUpOptions {
  email: string;
  password: string;
  name?: string;
  givenName?: string;
  familyName?: string;
  turnstileToken?: string;
}

export interface MagicLinkOptions {
  email: string;
  redirectUrl?: string;
  turnstileToken?: string;
}

export interface OAuthOptions {
  provider: 'google' | 'github' | 'microsoft' | string;
  redirectUrl?: string;
}

export interface ForgotPasswordOptions {
  email: string;
  redirectUrl?: string;
}

export interface ResetPasswordOptions {
  token: string;
  password: string;
}

export interface VerifyEmailOptions {
  token: string;
}

// ============================================================================
// MFA Types
// ============================================================================

export interface MfaChallenge {
  method: MfaMethod;
  expiresAt: string;
}

export interface MfaSetupOptions {
  method: Exclude<MfaMethod, 'backup_codes'>;
}

export interface MfaVerifyOptions {
  code: string;
  method: MfaMethod;
}

export interface TotpSetup {
  secret: string;
  qrCode: string;
  backupCodes: string[];
}

// ============================================================================
// WebAuthn Types
// ============================================================================

export interface WebAuthnOptions {
  challenge: string;
  rp: {
    id: string;
    name: string;
  };
  user: {
    id: string;
    displayName: string;
    name: string;
  };
  pubKeyCredParams: Array<{
    alg: number;
    type: string;
  }>;
  timeout: number;
  authenticatorSelection: {
    authenticatorAttachment?: string;
    requireResidentKey: boolean;
    residentKey: string;
    userVerification: string;
  };
  attestation: string;
}

export interface WebAuthnCredential {
  id: string;
  rawId: ArrayBuffer;
  response: AuthenticatorAttestationResponse | AuthenticatorAssertionResponse;
  type: string;
}

// ============================================================================
// Error Types
// ============================================================================

export interface ApiError {
  code: string;
  message: string;
  details?: Record<string, any>;
}

export type AuthState =
  | { status: 'loading' }
  | { status: 'authenticated'; user: User; session: Session }
  | { status: 'unauthenticated' }
  | { status: 'mfa_required'; challenge: MfaChallenge }
  | { status: 'error'; error: ApiError };

// ============================================================================
// Appearance Types
// ============================================================================

export interface Appearance {
  /** Base theme - 'light', 'dark', 'neutral', or 'auto' */
  baseTheme?: 'light' | 'dark' | 'neutral' | 'auto';
  /** CSS variable overrides */
  variables?: Record<string, string>;
  /** Layout configuration */
  layout?: {
    socialButtonsPlacement?: 'top' | 'bottom';
    socialButtonsVariant?: 'iconButton' | 'blockButton' | 'auto';
    showOptionalFields?: boolean;
    shimmer?: boolean;
    logoUrl?: string;
    logoPlacement?: 'inside' | 'outside' | 'none';
  };
  /** Additional CSS to inject */
  appendCss?: string;
}

// ============================================================================
// Component Prop Types
// ============================================================================

export interface SignInProps {
  redirectUrl?: string;
  oauthProviders?: Array<'google' | 'github' | 'microsoft'>;
  showMagicLink?: boolean;
  showForgotPassword?: boolean;
  showWebAuthn?: boolean;
  appearance?: Appearance;
  class?: string;
}

export interface SignUpProps {
  redirectUrl?: string;
  oauthProviders?: Array<'google' | 'github' | 'microsoft'>;
  requireName?: boolean;
  appearance?: Appearance;
  class?: string;
}

export interface UserButtonProps {
  showName?: boolean;
  avatarUrl?: string;
  menuItems?: Array<{
    label: string;
    onClick: () => void;
  }>;
  showManageAccount?: boolean;
  appearance?: Appearance;
  class?: string;
}

export interface UserProfileProps {
  onUpdate?: (user: User) => void;
  appearance?: Appearance;
  class?: string;
}

export interface ProtectProps {
  role?: OrganizationRole;
  permission?: string;
  fallback?: () => any;
  loading?: () => any;
}

export interface WebAuthnButtonProps {
  mode?: 'signin' | 'signup' | 'link';
  label?: string;
  onSuccess?: () => void;
  onError?: (error: ApiError) => void;
  appearance?: Appearance;
  class?: string;
}

export interface OrganizationSwitcherProps {
  hidePersonal?: boolean;
  onSwitch?: (org: Organization | null) => void;
  appearance?: Appearance;
  class?: string;
}

// ============================================================================
// Vault Context Type
// ============================================================================

export interface VaultContextValue {
  // State (Refs for Vue reactivity)
  isLoaded: Ref<boolean>;
  isSignedIn: Ref<boolean>;
  user: Ref<User | null>;
  session: Ref<Session | null>;
  organization: Ref<Organization | null>;
  organizations: Ref<Organization[]>;
  authState: Ref<AuthState>;
  mfaChallenge: Ref<MfaChallenge | null>;
  lastError: Ref<ApiError | null>;

  // Auth methods
  signIn: (options: SignInOptions) => Promise<void>;
  signInWithMagicLink: (options: MagicLinkOptions) => Promise<void>;
  signInWithOAuth: (options: OAuthOptions) => Promise<void>;
  signUp: (options: SignUpOptions) => Promise<void>;
  signOut: () => Promise<void>;

  // Password reset
  sendForgotPassword: (options: ForgotPasswordOptions) => Promise<void>;
  resetPassword: (options: ResetPasswordOptions) => Promise<{ user: User; session: Session }>;

  // Email verification
  verifyEmail: (options: VerifyEmailOptions) => Promise<void>;
  resendVerificationEmail: () => Promise<void>;

  // MFA
  verifyMfa: (code: string, method: MfaMethod) => Promise<void>;
  setupTotp: () => Promise<TotpSetup | null>;
  verifyTotpSetup: (code: string) => Promise<void>;
  disableMfa: (method: MfaMethod) => Promise<void>;
  generateBackupCodes: () => Promise<string[]>;

  // User methods
  updateUser: (updates: Partial<User>) => Promise<void>;
  reloadUser: () => Promise<void>;
  changePassword: (currentPassword: string, newPassword: string) => Promise<void>;
  deleteUser: () => Promise<void>;

  // Organization methods
  setActiveOrganization: (orgId: string | null) => Promise<void>;
  createOrganization: (name: string, slug?: string) => Promise<Organization>;
  leaveOrganization: (orgId: string) => Promise<void>;
  refreshOrganizations: () => Promise<void>;

  // Session methods
  getToken: () => Promise<string | null>;
  refreshSession: () => Promise<void>;
  setSessionTokens: (session: Session) => Promise<void>;

  // Error handling
  clearError: () => void;
}

// Injection key for Vue provide/inject
export const VaultInjectionKey: InjectionKey<VaultContextValue> = Symbol('vault');

// ============================================================================
// Composable Return Types
// ============================================================================

export interface UseAuthReturn {
  isLoaded: Ref<boolean>;
  isSignedIn: Ref<boolean>;
  user: Ref<User | null>;
  session: Ref<Session | null>;
  organization: Ref<Organization | null>;
  signIn: (options: SignInOptions) => Promise<void>;
  signInWithMagicLink: (options: MagicLinkOptions) => Promise<void>;
  signInWithOAuth: (options: OAuthOptions) => Promise<void>;
  signUp: (options: SignUpOptions) => Promise<void>;
  signOut: () => Promise<void>;
}

export interface UseSignInReturn {
  isLoading: Ref<boolean>;
  error: Ref<ApiError | null>;
  signIn: (options: SignInOptions) => Promise<void>;
  signInWithMagicLink: (options: MagicLinkOptions) => Promise<void>;
  signInWithOAuth: (options: OAuthOptions) => Promise<void>;
  resetError: () => void;
}

export interface UseSignUpReturn {
  isLoading: Ref<boolean>;
  error: Ref<ApiError | null>;
  signUp: (options: SignUpOptions) => Promise<void>;
  signUpWithOAuth: (options: OAuthOptions) => Promise<void>;
  resetError: () => void;
}

export interface UseSessionReturn {
  session: Ref<Session | null>;
  isLoaded: Ref<boolean>;
  getToken: () => Promise<string | null>;
  refresh: () => Promise<void>;
}

export interface UseUserReturn {
  user: Ref<User | null>;
  isLoaded: Ref<boolean>;
  update: (updates: Partial<User>) => Promise<void>;
  reload: () => Promise<void>;
}

export interface UseWebAuthnReturn {
  isSupported: Ref<boolean>;
  isLoading: Ref<boolean>;
  error: Ref<ApiError | null>;
  register: (name?: string) => Promise<void>;
  authenticate: () => Promise<Session | null>;
  resetError: () => void;
}

export interface UseMfaReturn {
  isLoading: Ref<boolean>;
  error: Ref<ApiError | null>;
  setupTotp: () => Promise<TotpSetup | null>;
  verifyTotp: (code: string) => Promise<void>;
  enableMfa: (method: MfaMethod) => Promise<void>;
  disableMfa: (method: MfaMethod) => Promise<void>;
  generateBackupCodes: () => Promise<string[]>;
  resetError: () => void;
}

export interface UseOrganizationReturn {
  organization: Ref<Organization | null>;
  organizations: Ref<Organization[]>;
  isLoaded: Ref<boolean>;
  isLoading: Ref<boolean>;
  members: Ref<OrganizationMember[]>;
  setActive: (orgId: string | null) => void;
  setActiveOrganization: (orgId: string | null) => Promise<void>;
  create: (data: { name: string; slug?: string }) => Promise<Organization>;
  createOrganization: (name: string, slug?: string) => Promise<Organization>;
  leave: (orgId: string) => Promise<void>;
  refreshMembers: () => Promise<void>;
  updateOrganization: (orgId: string, updates: Partial<Organization>) => Promise<Organization>;
  deleteOrganization: (orgId: string) => Promise<void>;
  inviteMember: (orgId: string, email: string, role: OrganizationRole) => Promise<void>;
  removeMember: (orgId: string, userId: string) => Promise<void>;
  updateMemberRole: (orgId: string, userId: string, role: OrganizationRole) => Promise<void>;
}

export interface UsePermissionsReturn {
  has: (permission: string) => boolean;
  hasRole: (role: string | string[]) => boolean;
  hasAnyRole: (roles: string[]) => boolean;
  permissions: Ref<string[]>;
  role: Ref<OrganizationRole | null>;
  isLoaded: Ref<boolean>;
}

export interface UseSessionsReturn {
  sessions: Ref<SessionInfo[]>;
  isLoading: Ref<boolean>;
  error: Ref<ApiError | null>;
  revokeSession: (sessionId: string) => Promise<void>;
  revokeAllOtherSessions: () => Promise<void>;
  refresh: () => Promise<void>;
}
