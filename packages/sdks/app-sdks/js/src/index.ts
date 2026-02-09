/**
 * Vault React SDK
 *
 * A comprehensive React SDK for Vault authentication and user management.
 *
 * @example
 * ```tsx
 * import { VaultProvider, useAuth, SignIn } from '@vault/react';
 *
 * function App() {
 *   return (
 *     <VaultProvider
 *       config={{
 *         apiUrl: "https://api.vault.dev",
 *         tenantId: "my-tenant"
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
 *     return <SignIn />;
 *   }
 *
 *   return <div>Hello {user?.email}!</div>;
 * }
 * ```
 */

// ============================================================================
// Context & Provider
// ============================================================================

export {
  VaultProvider,
  useVault,
  VaultContext
} from './context/VaultContext';

export type {
  VaultProviderProps
} from './context/VaultContext';

// ============================================================================
// Theme System
// ============================================================================

export {
  // Provider & Hook
  ThemeProvider,
  useTheme,
  withTheme,
  ThemeContext,
  // Default Themes
  lightTheme,
  darkTheme,
  neutralTheme,
  themes,
  getTheme,
  // Utilities
  mergeThemes,
  generateCSSVariables,
  cssVariablesToStyle,
  createElementStyles,
  getElementClasses,
  getLayoutOption,
  applyCSSVariables,
  cx,
  generateBaseStyles,
} from './theme';

export type {
  // Types
  ThemeVariables,
  ElementStyles,
  LayoutOptions,
  Appearance,
  Theme,
  ThemeContextValue,
  ThemeProviderProps,
  BaseComponentStyles,
} from './theme';

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
  useUpdateUser,
  useUserManager,

  // Session hooks
  useSession,
  useToken,
  useSessions,
  useSessionId,

  // Sign in/up hooks
  useSignIn,
  useSignUp,

  // WebAuthn hooks
  useWebAuthn,
  useIsWebAuthnSupported,

  // MFA hooks
  useMfa,
  useMfaChallenge,

  // Organization hooks
  useOrganization,
  useActiveOrganization,
  useOrganizationRole,
  useIsOrgAdmin,

  // Permission hooks
  usePermissions,
  useCheckAuthorization,

  // Billing hooks
  useBilling,
  useSubscription,
  useUsage,
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
  WebAuthnButton,
  VerifyEmail,
  ResetPassword,
  MFAForm,

  // Organization Components
  OrganizationSwitcher,
  CreateOrganization,
  OrganizationProfile,
  OrganizationList,

  // Session Components
  SessionManagement,

  // Utility Components
  Waitlist,
  ImpersonationBanner,

  // Control Components
  SignedIn,
  SignedOut,
  RequireAuth,

  // Route Protection
  Protect,
  RedirectToSignIn,
  RedirectToSignUp,

  // Billing Components
  PricingTable,
  CheckoutButton,
  QuickCheckoutButton,
  CustomerPortalButton,
  ManageSubscriptionButton,
  UpdatePaymentMethodButton,
  ViewInvoicesButton,
  BillingSettings,
  SubscriptionStatus,
  UsageMeter,
  InvoiceList,

  // UI Components
  Button,
  Input,
  Card,
  CardHeader,
  CardContent,
  CardFooter,
  Divider,
  Header,
  SocialButton,
  SocialButtons,
  Alert,
  Spinner,
  SpinnerOverlay,
  Skeleton,
} from './components';

// ============================================================================
// Component Types
// ============================================================================

export type {
  // Auth Components
  SignInProps,
  SignUpProps,
  UserButtonProps,
  UserProfileProps,
  WebAuthnButtonProps,
  VerifyEmailProps,
  ResetPasswordProps,
  MFAFormProps,

  // Organization Components
  OrganizationSwitcherProps,
  OrganizationSwitcherExtendedProps,
  CreateOrganizationProps,
  OrganizationProfileProps,
  OrganizationListProps,

  // Session Components
  SessionManagementProps,

  // Utility Components
  WaitlistProps,
  ImpersonationBannerProps,

  // Control Components
  SignedInProps,
  SignedOutProps,
  RequireAuthProps,

  // Route Protection
  ProtectProps,

  // Billing Component Props
  PricingTableProps,
  CheckoutButtonProps,
  QuickCheckoutButtonProps,
  CustomerPortalButtonProps,
  BillingSettingsProps,
  SubscriptionStatusProps,
  UsageMeterProps,
  InvoiceListProps,

  // UI Components
  ButtonProps,
  InputProps,
  CardProps,
  CardHeaderProps,
  CardContentProps,
  CardFooterProps,
  DividerProps,
  HeaderProps,
  SocialButtonProps,
  SocialButtonsProps,
  OAuthProvider,
  AlertProps,
  AlertVariant,
  SpinnerProps,
  SpinnerOverlayProps,
  SkeletonProps,
} from './components';

// ============================================================================
// Types
// ============================================================================

export type {
  // Core types
  User,
  UserProfile as UserProfileType,
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

  // Billing types
  BillingPlan,
  PlanTier,
  Subscription,
  SubscriptionStatus as SubscriptionStatusType,
  Invoice,
  InvoiceStatus,
  PaymentMethod,
  UsageSummary,
  UsageMetric,
  CheckoutSession,
  PortalSession,
  CreateCheckoutOptions,
  CreatePortalOptions,
  SubscriptionLimits,

  // Config types
  VaultConfig,
  Appearance as ComponentAppearance,

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

  // Hook return types
  UseAuthReturn,
  UseSignInReturn,
  UseSignUpReturn,
  UseSessionReturn,
  UseUserReturn,
  UseWebAuthnReturn,
  UseMfaReturn,
  UseOrganizationReturn,
  UseSessionsReturn,
  UsePermissionsReturn,
  UseCheckAuthorizationReturn,
} from './types';

// ============================================================================
// API Client
// ============================================================================

export {
  VaultApiClient,
  createVaultClient
} from './api/client';

// ============================================================================
// Zero-Knowledge Module
// ============================================================================

export {
  // Key derivation
  deriveMasterKey,
  exportMasterKey,
  importMasterKey,
  generateSalt,
  encryptPrivateKeyForStorage,
  decryptPrivateKeyFromStorage,
  generatePasswordCommitment,
  DEFAULT_ARGON2_PARAMS,
  CONSERVATIVE_ARGON2_PARAMS,
  FAST_ARGON2_PARAMS,

  // Encryption
  generateDek,
  wrapDek,
  unwrapDek,
  aesGcmEncrypt,
  aesGcmDecrypt,
  encryptUserData,
  decryptUserData,
  encryptWithMasterKey,
  decryptWithMasterKey,
  serializeEncryptedData,
  deserializeEncryptedData,

  // Proofs
  ZkPasswordProver,
  ZkPasswordVerifier,
  ZkAuthentication,
  generateChallenge,
  serializeProof,
  deserializeProof,

  // Recovery
  SocialRecovery,
  ShareValidator,
  RecoverySessionManager,
  RecoverySessionStatus,

  // Utils
  isWebCryptoAvailable,
  initZk,
  ZK_VERSION,

  // Errors
  ZkError,
  ZkEncryptionError,
  ZkKeyDerivationError,
  ZkProofError,
  ZkRecoveryError,
} from './zk';

export type {
  MasterKey,
  Argon2Params,
  DataEncryptionKey,
  WrappedDek,
  EncryptedUserData,
  UserProfile as ZkUserProfile,
  Address,
  ZkPasswordProof,
  RecoveryShare,
  ShareMetadata,
  RecoverySession,
} from './zk';

// ============================================================================
// Utilities
// ============================================================================

export {
  // OAuth utilities
  oauthProviderMetadata,
  oauthProviderCategories,
  getAllOAuthProviders,
  getOAuthProvidersByCategory,
  getOAuthProviderMetadata,
  getOAuthProviderDisplayName,
  getOAuthProviderColor,
  isPkceEnabled,
  getOAuthProviderDefaultScopes,
  getPopularOAuthProviders,
  getRecommendedOAuthProviders,
  isValidOAuthProvider,
  groupProvidersByCategory,
} from './utils';

// ============================================================================
// Version
// ============================================================================

export const VERSION = '0.1.0';
