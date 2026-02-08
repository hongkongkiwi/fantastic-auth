/**
 * Vault React UI Types
 * 
 * TypeScript types for the Vault React UI components.
 */

import { User, Organization, SessionInfo, ApiError, MfaMethod } from '@vault/react';

// ============================================================================
// Auth Types
// ============================================================================

export interface LoginCredentials {
  email: string;
  password: string;
}

export interface SignupData {
  email: string;
  password: string;
  name?: string;
  phone?: string;
  organization?: string;
}

export interface AuthError {
  code: string;
  message: string;
  field?: string;
}

// ============================================================================
// Theme Types
// ============================================================================

export type Theme = 'light' | 'dark' | 'auto';

export interface ThemeVariables {
  primary?: string;
  primaryHover?: string;
  primaryActive?: string;
  error?: string;
  success?: string;
  warning?: string;
  background?: string;
  surface?: string;
  text?: string;
  textMuted?: string;
  border?: string;
  borderRadius?: string;
  fontFamily?: string;
  fontSize?: string;
  spacing?: string;
}

// ============================================================================
// Component Props
// ============================================================================

export interface LoginFormProps {
  /** Callback after successful login */
  onSuccess?: (user: User) => void;
  /** Callback on login error */
  onError?: (error: AuthError) => void;
  /** URL to redirect after successful login */
  redirectUrl?: string;
  /** Show signup link */
  showSignupLink?: boolean;
  /** Show forgot password link */
  showForgotPassword?: boolean;
  /** Enable social login providers */
  socialProviders?: ('google' | 'github' | 'microsoft')[];
  /** Enable magic link login */
  enableMagicLink?: boolean;
  /** Theme variant */
  theme?: Theme;
  /** Custom CSS class */
  className?: string;
  /** Custom styles */
  style?: React.CSSProperties;
}

export interface SignupFormProps {
  /** Callback after successful signup */
  onSuccess?: (user: User) => void;
  /** Callback on signup error */
  onError?: (error: AuthError) => void;
  /** Require email verification */
  requireEmailVerification?: boolean;
  /** Allowed email domains (empty = all allowed) */
  allowedDomains?: string[];
  /** Additional fields to show */
  fields?: ('name' | 'phone' | 'organization')[];
  /** Terms of service URL */
  termsUrl?: string;
  /** Privacy policy URL */
  privacyUrl?: string;
  /** Enable social signup providers */
  socialProviders?: ('google' | 'github' | 'microsoft')[];
  /** Theme variant */
  theme?: Theme;
  /** Custom CSS class */
  className?: string;
  /** Custom styles */
  style?: React.CSSProperties;
}

export interface PasswordResetFormProps {
  /** Reset token (from URL query param for initial reset) */
  token?: string;
  /** Callback after successful password reset request/submission */
  onSuccess?: () => void;
  /** Callback on error */
  onError?: (error: AuthError) => void;
  /** URL to redirect after successful reset */
  redirectUrl?: string;
  /** Theme variant */
  theme?: Theme;
  /** Custom CSS class */
  className?: string;
  /** Custom styles */
  style?: React.CSSProperties;
}

export interface MFASetupProps {
  /** Available MFA methods to setup */
  methods?: MfaMethod[];
  /** Callback after successful MFA setup */
  onSuccess?: () => void;
  /** Callback on error */
  onError?: (error: AuthError) => void;
  /** Callback when user cancels */
  onCancel?: () => void;
  /** Theme variant */
  theme?: Theme;
  /** Custom CSS class */
  className?: string;
  /** Custom styles */
  style?: React.CSSProperties;
}

export interface UserProfileProps {
  /** Callback when profile is updated */
  onUpdate?: (user: User) => void;
  /** Callback on error */
  onError?: (error: AuthError) => void;
  /** Show account deletion option */
  showDeleteAccount?: boolean;
  /** Show password change option */
  showChangePassword?: boolean;
  /** Theme variant */
  theme?: Theme;
  /** Custom CSS class */
  className?: string;
  /** Custom styles */
  style?: React.CSSProperties;
}

export interface OrganizationSwitcherProps {
  /** Hide personal workspace option */
  hidePersonal?: boolean;
  /** Callback when organization is switched */
  onSwitch?: (org: Organization | null) => void;
  /** Callback when creating new organization */
  onCreate?: () => void;
  /** Theme variant */
  theme?: Theme;
  /** Custom CSS class */
  className?: string;
  /** Custom styles */
  style?: React.CSSProperties;
}

export interface SessionListProps {
  /** Callback when a session is revoked */
  onRevoke?: (sessionId: string) => void;
  /** Callback when all other sessions are revoked */
  onRevokeAll?: () => void;
  /** Show device information */
  showDeviceInfo?: boolean;
  /** Show location information */
  showLocation?: boolean;
  /** Theme variant */
  theme?: Theme;
  /** Custom CSS class */
  className?: string;
  /** Custom styles */
  style?: React.CSSProperties;
}

// ============================================================================
// Hook Return Types
// ============================================================================

export interface UseAuthReturn {
  /** Current user or null if not authenticated */
  user: User | null;
  /** Loading state */
  isLoading: boolean;
  /** Authentication status */
  isAuthenticated: boolean;
  /** Login with credentials */
  login: (credentials: LoginCredentials) => Promise<void>;
  /** Logout current user */
  logout: () => Promise<void>;
  /** Register new user */
  signup: (data: SignupData) => Promise<void>;
  /** Request password reset */
  resetPassword: (email: string) => Promise<void>;
  /** Complete password reset with token */
  completePasswordReset: (token: string, newPassword: string) => Promise<void>;
  /** Last error that occurred */
  error: AuthError | null;
  /** Clear error state */
  clearError: () => void;
}

export interface UseUserReturn {
  /** Current user or null */
  user: User | null;
  /** Loading state */
  isLoading: boolean;
  /** Update user profile */
  update: (updates: Partial<User>) => Promise<void>;
  /** Reload user data */
  reload: () => Promise<void>;
  /** Change password */
  changePassword: (currentPassword: string, newPassword: string) => Promise<void>;
  /** Delete account */
  deleteAccount: () => Promise<void>;
  /** Error state */
  error: AuthError | null;
}

export interface UseOrganizationReturn {
  /** Current active organization */
  organization: Organization | null;
  /** All user's organizations */
  organizations: Organization[];
  /** Loading state */
  isLoading: boolean;
  /** Set active organization */
  setActive: (orgId: string | null) => Promise<void>;
  /** Create new organization */
  create: (name: string, slug?: string) => Promise<Organization>;
  /** Leave organization */
  leave: (orgId: string) => Promise<void>;
  /** Refresh organizations list */
  refresh: () => Promise<void>;
  /** Error state */
  error: AuthError | null;
}

// ============================================================================
// Context Types
// ============================================================================

export interface VaultAuthProviderProps {
  /** API key for Vault */
  apiKey: string;
  /** Base URL for Vault API */
  baseUrl: string;
  /** Child components */
  children: React.ReactNode;
  /** Callback when auth state changes */
  onAuthChange?: (user: User | null) => void;
  /** Default theme */
  defaultTheme?: Theme;
  /** Custom theme variables */
  themeVariables?: ThemeVariables;
}

export interface VaultAuthContextValue extends UseAuthReturn {
  /** API configuration */
  config: {
    apiKey: string;
    baseUrl: string;
  };
  /** Current theme */
  theme: Theme;
  /** Set theme */
  setTheme: (theme: Theme) => void;
}

// ============================================================================
// UI Component Types
// ============================================================================

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  /** Button variant */
  variant?: 'primary' | 'secondary' | 'outline' | 'ghost' | 'danger';
  /** Button size */
  size?: 'sm' | 'md' | 'lg';
  /** Loading state */
  isLoading?: boolean;
  /** Full width button */
  fullWidth?: boolean;
}

export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  /** Input label */
  label?: string;
  /** Error message */
  error?: string;
  /** Helper text */
  helperText?: string;
  /** Input size */
  size?: 'sm' | 'md' | 'lg';
}

export interface AlertProps {
  /** Alert variant */
  variant?: 'info' | 'success' | 'warning' | 'error';
  /** Alert title */
  title?: string;
  /** Alert message */
  children: React.ReactNode;
  /** Dismissible alert */
  onDismiss?: () => void;
}

export interface SpinnerProps {
  /** Spinner size */
  size?: 'sm' | 'md' | 'lg';
  /** Custom class name */
  className?: string;
}

export interface SocialButtonProps {
  /** OAuth provider */
  provider: 'google' | 'github' | 'microsoft';
  /** Button variant */
  variant?: 'icon' | 'full';
  /** Loading state */
  isLoading?: boolean;
  /** Click handler */
  onClick?: () => void;
}
