/**
 * Vault SDK Types
 * 
 * TypeScript types for the Vault authentication SDK.
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

/**
 * @deprecated Use Appearance from '../theme' instead
 * Component appearance configuration
 */
export interface Appearance {
  /** Base theme - 'light', 'dark', 'neutral', or 'auto' */
  baseTheme?: 'light' | 'dark' | 'neutral' | 'auto';
  /** @deprecated Use baseTheme instead */
  theme?: 'light' | 'dark' | 'auto';
  /** CSS variable overrides */
  variables?: Record<string, string>;
  /** Element style overrides (deprecated, use class names instead) */
  elements?: Record<string, React.CSSProperties>;
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
   * Child components to render when authenticated
   */
  children: React.ReactNode;
  /**
   * Content to render when unauthenticated (default: redirects to sign in)
   */
  fallback?: React.ReactNode;
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
  loading?: React.ReactNode;
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

export interface VerifyEmailProps {
  /**
   * Verification token (from URL query param)
   */
  token?: string;
  /**
   * Callback on successful verification
   */
  onVerified?: () => void;
  /**
   * Callback on error
   */
  onError?: (error: ApiError) => void;
  /**
   * Redirect URL after verification
   */
  redirectUrl?: string;
  /**
   * Custom styling
   */
  appearance?: Appearance;
  /**
   * Custom class name
   */
  className?: string;
}

export interface ResetPasswordProps {
  /**
   * Reset token (from URL query param)
   */
  token?: string;
  /**
   * Callback on successful reset
   */
  onSuccess?: () => void;
  /**
   * Callback on error
   */
  onError?: (error: ApiError) => void;
  /**
   * Redirect URL after reset
   */
  redirectUrl?: string;
  /**
   * Custom styling
   */
  appearance?: Appearance;
  /**
   * Custom class name
   */
  className?: string;
}

export interface MFAFormProps {
  /**
   * MFA challenge (from auth context)
   */
  challenge?: MfaChallenge;
  /**
   * Callback on successful verification
   */
  onVerify?: () => void;
  /**
   * Callback on error
   */
  onError?: (error: ApiError) => void;
  /**
   * Allow backup code fallback
   */
  allowBackupCode?: boolean;
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

export interface CreateOrganizationProps {
  /**
   * Callback after successful organization creation
   */
  onCreate?: (org: Organization) => void;
  /**
   * Callback when user cancels
   */
  onCancel?: () => void;
  /**
   * Redirect URL after successful creation
   */
  redirectUrl?: string;
  /**
   * Skip the invitation screen after creation
   */
  skipInvitationScreen?: boolean;
  /**
   * Custom styling
   */
  appearance?: Appearance;
  /**
   * Custom class name
   */
  className?: string;
}

export interface OrganizationProfileProps {
  /**
   * Organization to display (defaults to active organization)
   */
  organization?: Organization;
  /**
   * Custom styling
   */
  appearance?: Appearance;
  /**
   * Custom class name
   */
  className?: string;
}

export interface OrganizationListProps {
  /**
   * Callback when an organization is selected
   */
  onSelect?: (org: Organization) => void;
  /**
   * Hide the create organization button
   */
  hideCreateButton?: boolean;
  /**
   * Custom styling
   */
  appearance?: Appearance;
  /**
   * Custom class name
   */
  className?: string;
}

export interface SessionManagementProps {
  /**
   * Custom styling
   */
  appearance?: Appearance;
  /**
   * Custom class name
   */
  className?: string;
}

export interface WaitlistProps {
  /**
   * Callback when email is submitted
   */
  onSubmit?: (email: string) => void;
  /**
   * Redirect URL after successful submission
   */
  redirectUrl?: string;
  /**
   * Custom styling
   */
  appearance?: Appearance;
  /**
   * Social proof text (e.g., "Join 1,000+ others")
   */
  socialProof?: string;
  /**
   * Custom class name
   */
  className?: string;
}

export interface ImpersonationBannerProps {
  /**
   * Callback when user clicks "Stop Impersonating"
   */
  onStopImpersonating?: () => void;
}

export interface SignedInProps {
  children: React.ReactNode;
}

export interface SignedOutProps {
  children: React.ReactNode;
}

export interface RedirectToSignInProps {
  /**
   * URL to redirect back to after sign in
   */
  redirectUrl?: string;
}

export interface RedirectToSignUpProps {
  /**
   * URL to redirect back to after sign up
   */
  redirectUrl?: string;
}

// ============================================================================
// Hook Return Types
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

export interface UseSessionReturn {
  session: Session | null;
  isLoaded: boolean;
  getToken: () => Promise<string | null>;
  refresh: () => Promise<void>;
}

export interface UseUserReturn {
  user: User | null;
  isLoaded: boolean;
  update: (updates: Partial<User>) => Promise<void>;
  reload: () => Promise<void>;
}

export interface UseWebAuthnReturn {
  isSupported: boolean;
  isLoading: boolean;
  error: ApiError | null;
  register: (name?: string) => Promise<void>;
  authenticate: () => Promise<Session | null>;
  resetError: () => void;
}

export interface UseMfaReturn {
  isLoading: boolean;
  error: ApiError | null;
  setupTotp: () => Promise<TotpSetup | null>;
  verifyTotp: (code: string) => Promise<void>;
  enableMfa: (method: MfaMethod) => Promise<void>;
  disableMfa: (method: MfaMethod) => Promise<void>;
  generateBackupCodes: () => Promise<string[]>;
  resetError: () => void;
}

export interface UseOrganizationReturn {
  organization: Organization | null;
  organizations: Organization[];
  organizationList: Organization[];
  isLoaded: boolean;
  isLoading: boolean;
  members: OrganizationMember[];
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

export interface UseSessionsReturn {
  sessions: SessionInfo[];
  isLoading: boolean;
  error: ApiError | null;
  revokeSession: (sessionId: string) => Promise<void>;
  revokeAllOtherSessions: () => Promise<void>;
  refresh: () => Promise<void>;
}

export interface UsePermissionsReturn {
  has: (permission: string) => boolean;
  hasRole: (role: string | string[]) => boolean;
  hasAnyRole: (roles: string[]) => boolean;
  permissions: string[];
  role: OrganizationRole | null;
  isLoaded: boolean;
}

export interface UseCheckAuthorizationReturn {
  check: (params: PermissionCheck) => boolean;
}

// Re-export from vault-api (generated) if available
// export * from '../generated';
