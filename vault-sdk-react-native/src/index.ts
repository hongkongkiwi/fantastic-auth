/**
 * Vault React Native SDK
 * 
 * A comprehensive React Native SDK for Vault authentication and user management.
 * Features secure storage, biometric authentication, and offline support.
 * 
 * @example
 * ```tsx
 * import { VaultProvider, useAuth, SignIn } from '@vault/react-native';
 * 
 * function App() {
 *   return (
 *     <VaultProvider
 *       config={{
 *         apiUrl: "https://api.vault.dev",
 *         tenantId: "my-tenant",
 *         enableBiometricUnlock: true,
 *       }}
 *     >
 *       <YourApp />
 *     </VaultProvider>
 *   );
 * }
 * 
 * function YourApp() {
 *   const { isSignedIn, user, signOut } = useAuth();
 * 
 *   if (!isSignedIn) {
 *     return <SignIn oauthProviders={['google', 'apple']} />;
 *   }
 * 
 *   return <Text>Hello {user?.email}!</Text>;
 * }
 * ```
 */

// ============================================================================
// Provider
// ============================================================================

export {
  VaultProvider,
  useVault,
  VaultContext,
} from './VaultProvider';

export type {
  VaultProviderProps,
} from './types';

// ============================================================================
// Hooks
// ============================================================================

export {
  // Auth hooks
  useAuth,
  useAuthState,
  useHasRole,
  useRequireAuth,

  // User hooks
  useUser,
  useUserManager,

  // Session hooks
  useSession,
  useToken,
  useSessionId,
  useSessions,

  // Sign in/up hooks
  useSignIn,
  useSignUp,

  // WebAuthn hooks
  useWebAuthn,
  useIsWebAuthnSupported,
  useWebAuthnCredentials,

  // Organization hooks
  useOrganization,
  useActiveOrganization,
  useOrganizationList,
  useOrganizationRole,
  useIsOrgAdmin,
  useIsOrgOwner,

  // Biometric hooks
  useBiometricAuth,

  // Deep linking hooks
  useOAuthDeepLink,
} from './hooks';

// ============================================================================
// Components
// ============================================================================

export {
  // Auth Components
  SignIn,
  SignUp,
  UserButton,
  UserProfile,

  // Organization Components
  OrganizationSwitcher,

  // OAuth
  OAuthButton,
} from './components';

// ============================================================================
// Types
// ============================================================================

export type {
  // Core types
  User,
  Session,
  Organization,
  ApiError,
  VaultConfig,
  AppAuthState,

  // Auth option types
  SignInOptions,
  SignUpOptions,
  MagicLinkOptions,
  OAuthOptions,

  // Biometric types
  BiometricType,
  BiometricResult,
  UseBiometricAuthReturn,

  // Deep linking types
  OAuthCallbackData,
  DeepLinkHandler,
  UseOAuthDeepLinkReturn,

  // Hook return types
  UseAuthReturn,
  UseSignInReturn,
  UseSignUpReturn,
  UseSessionReturn,

  // Component prop types
  SignInProps,
  SignUpProps,
  UserButtonProps,
  UserProfileProps,
  OrganizationSwitcherProps,
  OAuthButtonProps,
} from './types';

// ============================================================================
// API Client
// ============================================================================

export {
  VaultApiClient,
  createVaultClient,
  getGlobalClient,
  setGlobalClient,
  clearGlobalClient,
} from './api';

// ============================================================================
// Secure Storage
// ============================================================================

export {
  // Main storage functions
  setItem,
  getItem,
  removeItem,
  hasItem,
  clearVaultStorage,
  isSecureStorageAvailable,
  SecureStorage,

  // Session token management
  storeSessionToken,
  getSessionToken,
  storeRefreshToken,
  getRefreshToken,
  clearSessionTokens,

  // User data caching
  storeCachedUser,
  getCachedUser,
  storeCachedOrganizations,
  getCachedOrganizations,

  // Biometric settings
  isBiometricEnabled,
  setBiometricEnabled,

  // Generic storage
  setGenericItem,
  getGenericItem,
  removeGenericItem,
} from './storage';

export type {
  SecureStorageOptions,
  SecureStorageItem,
} from './types';

// ============================================================================
// Biometric Authentication
// ============================================================================

export {
  // Core functions
  getBiometricType,
  isBiometricAuthAvailable,
  isBiometricEnrolled,
  authenticateWithBiometrics,
  createBiometricSignature,
  BiometricAuth,

  // Hook
  useBiometricAuth,
} from './biometric';

// ============================================================================
// Deep Linking
// ============================================================================

export {
  // Core functions
  parseOAuthCallback,
  buildOAuthUrl,
  openOAuthInAppBrowser,
  closeInAppBrowser,
  addDeepLinkListener,
  removeDeepLinkListener,
  OAuthHandler,

  // Hook
  useOAuthDeepLink,
} from './deep-linking';

// ============================================================================
// Version
// ============================================================================

export const VERSION = '0.1.0';
