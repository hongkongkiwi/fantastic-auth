/**
 * Vault React Native SDK Types
 * 
 * TypeScript types for the Vault React Native authentication SDK.
 */

import { 
  User, 
  Session, 
  Organization, 
  ApiError,
  VaultConfig as BaseVaultConfig,
  SignInOptions,
  SignUpOptions,
  MagicLinkOptions,
  OAuthOptions,
} from '@fantasticauth/react';

export type { 
  User, 
  Session, 
  Organization, 
  ApiError,
  SignInOptions,
  SignUpOptions,
  MagicLinkOptions,
  OAuthOptions,
} from '@fantasticauth/react';

// ============================================================================
// React Native Specific Configuration
// ============================================================================

/**
 * Vault configuration for React Native
 */
export interface VaultConfig extends BaseVaultConfig {
  /**
   * Enable biometric authentication for app unlock
   * @default false
   */
  enableBiometricUnlock?: boolean;
  
  /**
   * Biometric authentication prompt message
   * @default 'Verify your identity'
   */
  biometricPrompt?: string;
  
  /**
   * Custom OAuth redirect scheme
   * Used for deep linking back to the app
   * @default 'vault'
   */
  oauthRedirectScheme?: string;
  
  /**
   * Enable secure storage for session tokens
   * Uses Keychain (iOS) or Keystore (Android)
   * @default true
   */
  enableSecureStorage?: boolean;
  
  /**
   * Enable offline support
   * Cache user data and queue actions when offline
   * @default true
   */
  enableOfflineSupport?: boolean;
  
  /**
   * Session refresh interval in milliseconds
   * @default 300000 (5 minutes)
   */
  sessionRefreshInterval?: number;
}

// ============================================================================
// Biometric Authentication Types
// ============================================================================

/**
 * Biometric authentication types available on the device
 */
export type BiometricType = 'FaceID' | 'TouchID' | 'Fingerprint' | 'Iris' | 'none';

/**
 * Biometric authentication result
 */
export interface BiometricResult {
  success: boolean;
  error?: string;
}

/**
 * Biometric authentication hook return type
 */
export interface UseBiometricAuthReturn {
  /**
   * Whether biometric authentication is available on this device
   */
  isAvailable: boolean;
  
  /**
   * The type of biometric authentication available
   */
  biometricType: BiometricType;
  
  /**
   * Whether biometric authentication is currently loading
   */
  isLoading: boolean;
  
  /**
   * Authenticate using biometrics
   * @param promptMessage - Custom prompt message
   * @returns Promise resolving to authentication result
   */
  authenticate: (promptMessage?: string) => Promise<BiometricResult>;
  
  /**
   * Check if biometrics is enrolled on the device
   */
  checkEnrollment: () => Promise<boolean>;
}

// ============================================================================
// Secure Storage Types
// ============================================================================

/**
 * Secure storage service options
 */
export interface SecureStorageOptions {
  /**
   * Service name for iOS Keychain
   */
  service?: string;
  
  /**
   * Keychain accessibility level (iOS)
   */
  accessibility?: 'AfterFirstUnlock' | 'AfterFirstUnlockThisDeviceOnly' | 'Always' | 'AlwaysThisDeviceOnly' | 'WhenUnlocked' | 'WhenUnlockedThisDeviceOnly';
  
  /**
   * Storage type (Android)
   */
  storageType?: 'FB' | 'AES' | 'RSA';
}

/**
 * Secure storage item
 */
export interface SecureStorageItem {
  key: string;
  value: string;
  service?: string;
}

// ============================================================================
// Deep Linking Types
// ============================================================================

/**
 * OAuth callback data from deep link
 */
export interface OAuthCallbackData {
  provider: string;
  code: string;
  state?: string;
  error?: string;
  errorDescription?: string;
}

/**
 * Deep link handler callback
 */
export type DeepLinkHandler = (url: string, data: OAuthCallbackData | null) => void;

/**
 * OAuth deep link hook return type
 */
export interface UseOAuthDeepLinkReturn {
  /**
   * Last received OAuth callback data
   */
  lastCallback: OAuthCallbackData | null;
  
  /**
   * Whether OAuth flow is in progress
   */
  isOAuthInProgress: boolean;
  
  /**
   * Start OAuth flow
   * @param url - OAuth authorization URL
   */
  startOAuth: (url: string) => Promise<void>;
  
  /**
   * Complete OAuth flow with callback data
   * @param data - OAuth callback data
   */
  completeOAuth: (data: OAuthCallbackData) => Promise<void>;
  
  /**
   * Cancel ongoing OAuth flow
   */
  cancelOAuth: () => void;
}

// ============================================================================
// React Native Specific Hook Return Types
// ============================================================================

/**
 * Extended auth hook return type for React Native
 */
export interface UseAuthReturn {
  isLoaded: boolean;
  isSignedIn: boolean;
  user: User | null;
  session: Session | null;
  organization: Organization | null;
  
  /**
   * Whether the app is locked (biometric lock enabled)
   */
  isLocked: boolean;
  
  /**
   * Sign in with email/password
   */
  signIn: (options: SignInOptions) => Promise<void>;
  
  /**
   * Sign in with magic link
   */
  signInWithMagicLink: (options: MagicLinkOptions) => Promise<void>;
  
  /**
   * Sign in with OAuth provider
   */
  signInWithOAuth: (options: OAuthOptions) => Promise<void>;
  
  /**
   * Sign up with email/password
   */
  signUp: (options: SignUpOptions) => Promise<void>;
  
  /**
   * Sign out current user
   */
  signOut: () => Promise<void>;
  
  /**
   * Unlock the app with biometrics
   */
  unlockWithBiometrics: () => Promise<boolean>;
  
  /**
   * Lock the app (enable biometric lock)
   */
  lockApp: () => void;
}

/**
 * Sign in hook return type for React Native
 */
export interface UseSignInReturn {
  isLoading: boolean;
  error: ApiError | null;
  signIn: (options: SignInOptions) => Promise<void>;
  signInWithMagicLink: (options: MagicLinkOptions) => Promise<void>;
  signInWithOAuth: (options: OAuthOptions) => Promise<void>;
  signInWithBiometrics: () => Promise<void>;
  resetError: () => void;
}

/**
 * Sign up hook return type for React Native
 */
export interface UseSignUpReturn {
  isLoading: boolean;
  error: ApiError | null;
  signUp: (options: SignUpOptions) => Promise<void>;
  signUpWithOAuth: (options: OAuthOptions) => Promise<void>;
  resetError: () => void;
}

/**
 * Session hook return type for React Native
 */
export interface UseSessionReturn {
  session: Session | null;
  isLoaded: boolean;
  getToken: () => Promise<string | null>;
  refresh: () => Promise<void>;
  
  /**
   * Last token refresh timestamp
   */
  lastRefreshedAt: number | null;
}

// ============================================================================
// Component Prop Types
// ============================================================================

/**
 * Base component props for React Native
 */
export interface BaseComponentProps {
  /**
   * Callback when an error occurs
   */
  onError?: (error: ApiError) => void;
  
  /**
   * Custom styles
   */
  style?: any;
  
  /**
   * Test ID for testing
   */
  testID?: string;
}

/**
 * SignIn component props
 */
export interface SignInProps extends BaseComponentProps {
  /**
   * OAuth providers to show
   */
  oauthProviders?: Array<'google' | 'apple' | 'microsoft' | 'github'>;
  
  /**
   * Show magic link option
   */
  showMagicLink?: boolean;
  
  /**
   * Show biometric sign in option
   */
  showBiometricOption?: boolean;
  
  /**
   * Show forgot password link
   */
  showForgotPassword?: boolean;
  
  /**
   * Callback after successful sign in
   */
  onSignIn?: () => void;
  
  /**
   * Redirect URL after sign in
   */
  redirectUrl?: string;
}

/**
 * SignUp component props
 */
export interface SignUpProps extends BaseComponentProps {
  /**
   * OAuth providers to show
   */
  oauthProviders?: Array<'google' | 'apple' | 'microsoft' | 'github'>;
  
  /**
   * Require name field
   */
  requireName?: boolean;
  
  /**
   * Callback after successful sign up
   */
  onSignUp?: () => void;
  
  /**
   * Redirect URL after sign up
   */
  redirectUrl?: string;
}

/**
 * UserButton component props
 */
export interface UserButtonProps extends BaseComponentProps {
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
    onPress: () => void;
    icon?: string;
  }>;
  
  /**
   * Show manage account option
   */
  showManageAccount?: boolean;
}

/**
 * UserProfile component props
 */
export interface UserProfileProps extends BaseComponentProps {
  /**
   * Callback when profile is updated
   */
  onUpdate?: (user: User) => void;
}

/**
 * OAuthButton component props
 */
export interface OAuthButtonProps extends BaseComponentProps {
  /**
   * OAuth provider
   */
  provider: 'google' | 'apple' | 'microsoft' | 'github' | string;
  
  /**
   * Button variant
   */
  variant?: 'default' | 'icon-only';
  
  /**
   * Custom button text
   */
  text?: string;
  
  /**
   * Callback after OAuth flow completes
   */
  onSuccess?: () => void;
}

/**
 * OrganizationSwitcher component props
 */
export interface OrganizationSwitcherProps extends BaseComponentProps {
  /**
   * Hide personal organization option
   */
  hidePersonal?: boolean;
  
  /**
   * Callback when organization is switched
   */
  onSwitch?: (org: Organization | null) => void;
}

// ============================================================================
// App State Types
// ============================================================================

/**
 * App authentication state
 */
export type AppAuthState = 
  | { status: 'loading' }
  | { status: 'authenticated'; user: User; session: Session }
  | { status: 'unauthenticated' }
  | { status: 'locked' }
  | { status: 'offline'; user: User }
  | { status: 'error'; error: ApiError };

/**
 * Provider props
 */
export interface VaultProviderProps {
  children: React.ReactNode;
  
  /**
   * Vault configuration
   */
  config: VaultConfig;
  
  /**
   * Initial user data
   */
  initialUser?: User;
  
  /**
   * Callback when auth state changes
   */
  onAuthStateChange?: (state: AppAuthState) => void;
  
  /**
   * Loading component
   */
  loadingComponent?: React.ReactNode;
  
  /**
   * Biometric lock component
   */
  biometricLockComponent?: React.ReactNode;
}
