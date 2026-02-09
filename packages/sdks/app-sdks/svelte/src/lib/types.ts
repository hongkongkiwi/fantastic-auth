/**
 * Vault Svelte SDK Types
 * 
 * TypeScript types for the Vault Svelte SDK.
 * Compatible with both Svelte 4 and Svelte 5.
 */

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
// Component Prop Types
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

export interface SignInProps {
  /**
   * Redirect URL after successful sign in
   */
  redirectUrl?: string;
  /**
   * Callback after successful sign in
   */
  onSignIn?: () => void;
  /**
   * Callback on sign in error
   */
  onError?: (error: ApiError) => void;
  /**
   * Enable magic link option
   */
  showMagicLink?: boolean;
  /**
   * Enable forgot password link
   */
  showForgotPassword?: boolean;
  /**
   * Enable OAuth providers
   */
  oauthProviders?: Array<'google' | 'github' | 'microsoft'>;
  /**
   * Enable WebAuthn/passkey sign in
   */
  showWebAuthn?: boolean;
  /**
   * Custom styling
   */
  appearance?: Appearance;
  /**
   * Custom class name
   */
  className?: string;
}

export interface SignUpProps {
  /**
   * Redirect URL after successful sign up
   */
  redirectUrl?: string;
  /**
   * Callback after successful sign up
   */
  onSignUp?: () => void;
  /**
   * Callback on sign up error
   */
  onError?: (error: ApiError) => void;
  /**
   * Enable OAuth providers
   */
  oauthProviders?: Array<'google' | 'github' | 'microsoft'>;
  /**
   * Require name field
   */
  requireName?: boolean;
  /**
   * Custom styling
   */
  appearance?: Appearance;
  /**
   * Custom class name
   */
  className?: string;
}

export interface UserButtonProps {
  /**
   * Show user name in button
   */
  showName?: boolean;
  /**
   * Custom avatar URL
   */
  avatarUrl?: string;
  /**
   * Callback when sign out is clicked
   */
  onSignOut?: () => void;
  /**
   * Custom menu items
   */
  menuItems?: Array<{
    label: string;
    onClick: () => void;
  }>;
  /**
   * Show manage account link
   */
  showManageAccount?: boolean;
  /**
   * Custom styling
   */
  appearance?: Appearance;
  /**
   * Custom class name
   */
  className?: string;
}

export interface UserProfileProps {
  /**
   * Callback when profile is updated
   */
  onUpdate?: (user: User) => void;
  /**
   * Custom styling
   */
  appearance?: Appearance;
  /**
   * Custom class name
   */
  className?: string;
}

export interface ProtectProps {
  /**
   * Required role for access
   */
  role?: OrganizationRole;
  /**
   * Required permission
   */
  permission?: string;
  /**
   * Custom loading component
   */
  loading?: import('svelte').Snippet;
  /**
   * Content to render when unauthenticated
   */
  fallback?: import('svelte').Snippet;
  /**
   * Child components to render when authenticated
   */
  children: import('svelte').Snippet;
}

export interface WebAuthnButtonProps {
  /**
   * Button mode: 'signin' | 'signup' | 'link'
   */
  mode?: 'signin' | 'signup' | 'link';
  /**
   * Button label
   */
  label?: string;
  /**
   * Callback on success
   */
  onSuccess?: () => void;
  /**
   * Callback on error
   */
  onError?: (error: ApiError) => void;
  /**
   * Custom styling
   */
  appearance?: Appearance;
  /**
   * Custom class name
   */
  className?: string;
}

export interface OrganizationSwitcherProps {
  /**
   * Hide personal organization option
   */
  hidePersonal?: boolean;
  /**
   * Callback when organization is switched
   */
  onSwitch?: (org: Organization | null) => void;
  /**
   * Custom styling
   */
  appearance?: Appearance;
  /**
   * Custom class name
   */
  className?: string;
}

// ============================================================================
// Store/Hook Return Types
// ============================================================================

export interface UseAuthReturn {
  isLoaded: boolean;
  isSignedIn: boolean;
  user: User | null;
  session: Session | null;
  organization: Organization | null;
  signIn: (options: SignInOptions) => Promise<void>;
  signInWithMagicLink: (options: MagicLinkOptions) => Promise<void>;
  signInWithOAuth: (options: OAuthOptions) => Promise<void>;
  signUp: (options: SignUpOptions) => Promise<void>;
  signOut: () => Promise<void>;
}

export interface UseSignInReturn {
  isLoading: boolean;
  error: ApiError | null;
  signIn: (options: SignInOptions) => Promise<void>;
  signInWithMagicLink: (options: MagicLinkOptions) => Promise<void>;
  signInWithOAuth: (options: OAuthOptions) => Promise<void>;
  resetError: () => void;
}

export interface UseSignUpReturn {
  isLoading: boolean;
  error: ApiError | null;
  signUp: (options: SignUpOptions) => Promise<void>;
  signUpWithOAuth: (options: OAuthOptions) => Promise<void>;
  resetError: () => void;
}

export interface UseUserReturn {
  user: User | null;
  isLoaded: boolean;
  update: (updates: Partial<User>) => Promise<void>;
  reload: () => Promise<void>;
  changePassword: (currentPassword: string, newPassword: string) => Promise<void>;
  deleteUser: () => Promise<void>;
}

export interface UseSessionReturn {
  session: Session | null;
  isLoaded: boolean;
  getToken: () => Promise<string | null>;
  refresh: () => Promise<void>;
}

export interface UseOrganizationReturn {
  organization: Organization | null;
  organizations: Organization[];
  isLoaded: boolean;
  setActive: (orgId: string | null) => Promise<void>;
  create: (data: { name: string; slug?: string }) => Promise<Organization>;
  leave: (orgId: string) => Promise<void>;
  refresh: () => Promise<void>;
}

export interface UseMfaReturn {
  isLoading: boolean;
  error: ApiError | null;
  setupTotp: () => Promise<TotpSetup | null>;
  verifyTotp: (code: string) => Promise<void>;
  disableMfa: (method: MfaMethod) => Promise<void>;
  generateBackupCodes: () => Promise<string[]>;
  resetError: () => void;
}

export interface UseWebAuthnReturn {
  isSupported: boolean;
  isLoading: boolean;
  error: ApiError | null;
  register: (name?: string) => Promise<void>;
  authenticate: () => Promise<Session | null>;
  resetError: () => void;
}

// ============================================================================
// Context Types
// ============================================================================

export interface VaultContextValue {
  // State
  isLoaded: boolean;
  isSignedIn: boolean;
  user: User | null;
  session: Session | null;
  organization: Organization | null;
  authState: AuthState;
  
  // API Client (for advanced use cases)
  api: VaultApiClient;
  
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
  mfaChallenge: MfaChallenge | null;
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
  organizations: Organization[];
  setActiveOrganization: (orgId: string | null) => Promise<void>;
  createOrganization: (name: string, slug?: string) => Promise<Organization>;
  leaveOrganization: (orgId: string) => Promise<void>;
  refreshOrganizations: () => Promise<void>;
  
  // Session methods
  sessions: SessionInfo[];
  revokeSession: (sessionId: string) => Promise<void>;
  revokeAllOtherSessions: () => Promise<void>;
  refreshSessions: () => Promise<void>;
  
  // Token & Session
  getToken: () => Promise<string | null>;
  refreshSession: () => Promise<void>;
  
  // Error handling
  lastError: ApiError | null;
  clearError: () => void;
}

export interface VaultProviderProps {
  /**
   * Vault configuration
   */
  config: VaultConfig;
  /**
   * Child components
   */
  children: import('svelte').Snippet;
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
// API Client Types
// ============================================================================

export interface VaultApiClient {
  signIn(options: SignInOptions): Promise<{
    user: User;
    session: Session;
    mfaRequired?: boolean;
    mfaChallenge?: MfaChallenge;
  }>;
  signUp(options: SignUpOptions): Promise<{ user: User; session: Session }>;
  sendMagicLink(options: MagicLinkOptions): Promise<void>;
  verifyMagicLink(token: string): Promise<{ user: User; session: Session }>;
  sendForgotPassword(options: ForgotPasswordOptions): Promise<void>;
  resetPassword(options: ResetPasswordOptions): Promise<{ user: User; session: Session }>;
  verifyEmail(options: VerifyEmailOptions): Promise<{ user: User }>;
  resendVerificationEmail(): Promise<void>;
  getOAuthUrl(options: OAuthOptions): Promise<{ url: string }>;
  handleOAuthCallback(provider: string, code: string): Promise<{ user: User; session: Session }>;
  verifyMfa(code: string, method: MfaMethod): Promise<{ user: User; session: Session }>;
  signOut(): Promise<void>;
  refreshSession(): Promise<{ session: Session }>;
  validateSession(token: string): Promise<Session>;
  getCurrentUser(): Promise<User>;
  updateUser(updates: Partial<User> | Partial<UserProfile>): Promise<User>;
  deleteUser(): Promise<void>;
  changePassword(currentPassword: string, newPassword: string): Promise<void>;
  uploadAvatar(file: File): Promise<{ url: string }>;
  getMfaStatus(): Promise<{ enabled: boolean; methods: MfaMethod[] }>;
  setupTotp(): Promise<TotpSetup>;
  verifyTotpSetup(code: string): Promise<void>;
  disableMfa(method: MfaMethod): Promise<void>;
  generateBackupCodes(): Promise<{ codes: string[] }>;
  verifyBackupCode(code: string): Promise<void>;
  beginWebAuthnRegistration(): Promise<WebAuthnOptions>;
  finishWebAuthnRegistration(credential: unknown): Promise<void>;
  beginWebAuthnAuthentication(): Promise<WebAuthnOptions>;
  finishWebAuthnAuthentication(credential: unknown): Promise<{ user: User; session: Session }>;
  listWebAuthnCredentials(): Promise<Array<{ id: string; name: string; createdAt: string; lastUsedAt?: string }>>;
  deleteWebAuthnCredential(credentialId: string): Promise<void>;
  listSessions(): Promise<SessionInfo[]>;
  revokeSession(sessionId: string): Promise<void>;
  revokeAllSessions(): Promise<void>;
  listOrganizations(): Promise<Organization[]>;
  setActiveOrganization(orgId: string | null): Promise<{ user: User; session: Session }>;
  getOrganization(id: string): Promise<Organization>;
  createOrganization(data: { name: string; slug?: string }): Promise<Organization>;
  updateOrganization(id: string, data: Partial<Organization>): Promise<Organization>;
  deleteOrganization(id: string): Promise<void>;
  leaveOrganization(id: string): Promise<void>;
  listOrganizationMembers(orgId: string): Promise<OrganizationMember[]>;
  inviteOrganizationMember(orgId: string, email: string, role: string): Promise<void>;
  removeOrganizationMember(orgId: string, userId: string): Promise<void>;
  updateOrganizationMemberRole(orgId: string, userId: string, role: string): Promise<void>;
  storeToken(token: string): Promise<void>;
  storeRefreshToken(token: string): Promise<void>;
  getStoredToken(): Promise<string | null>;
  getStoredRefreshToken(): Promise<string | null>;
  clearToken(): Promise<void>;
  isWebAuthnSupported(): boolean;
}

// ============================================================================
// SvelteKit Server Types
// ============================================================================

export interface VaultAuthConfig {
  /**
   * Public routes that don't require authentication
   */
  publicRoutes?: string[];
  /**
   * Routes that require authentication (if specified, only these routes are protected)
   */
  protectedRoutes?: string[];
  /**
   * API URL
   */
  apiUrl: string;
  /**
   * Tenant ID
   */
  tenantId: string;
  /**
   * Redirect URL for unauthenticated users
   */
  signInUrl?: string;
}

export interface VaultLocals {
  user: User | null;
  session: Session | null;
  token: string | null;
}

// Re-export Svelte-specific types
export type { Snippet } from 'svelte';
