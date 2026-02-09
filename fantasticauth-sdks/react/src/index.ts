/**
 * Vault React UI
 * 
 * Pre-built React UI components for Vault authentication.
 * 
 * @example
 * ```tsx
 * import { VaultAuthProvider, LoginForm, useAuth } from '@vault/react-ui';
 * 
 * function App() {
 *   return (
 *     <VaultAuthProvider
 *       apiKey="your-api-key"
 *       baseUrl="https://api.vault.dev"
 *     >
 *       <YourApp />
 *     </VaultAuthProvider>
 *   );
 * }
 * 
 * function YourApp() {
 *   const { isAuthenticated, user } = useAuth();
 *   
 *   if (!isAuthenticated) {
 *     return <LoginForm />;
 *   }
 *   
 *   return <div>Welcome, {user.email}!</div>;
 * }
 * ```
 */

// ============================================================================
// Context & Provider
// ============================================================================

export {
  VaultAuthProvider,
  VaultAuthContext,
  useVaultAuthContext,
} from './context/VaultAuthContext';

// ============================================================================
// Hooks
// ============================================================================

export {
  // Auth hooks
  useAuth,
  useIsAuthLoading,
  useIsAuthenticated,
  useCurrentUser,
  useLogin,
  useSignup,
  useLogout,
  usePasswordReset,
  
  // User hooks
  useUser,
  useUserProfile,
  useIsEmailVerified,
  useIsMfaEnabled,
  
  // Organization hooks
  useOrganization,
  useHasActiveOrganization,
  useOrganizationRole,
  useIsOrgAdmin,
  useOrganizationCount,
} from './hooks';

// ============================================================================
// Components
// ============================================================================

export {
  // Auth components
  LoginForm,
  SignupForm,
  PasswordResetForm,
  MFASetup,
  UserProfile,
  
  // Organization components
  OrganizationSwitcher,
  
  // Session components
  SessionList,
  
  // UI components
  Button,
  Input,
  Alert,
  Spinner,
  SocialButton,
  SocialButtons,
} from './components';

// ============================================================================
// Styles
// ============================================================================

export {
  applyThemeVariables,
  getThemeClass,
  classNames,
  generateCustomThemeCSS,
} from './styles';

// ============================================================================
// Types
// ============================================================================

export type {
  // Auth types
  LoginCredentials,
  SignupData,
  AuthError,
  
  // Theme types
  Theme,
  ThemeVariables,
  
  // Component props
  LoginFormProps,
  SignupFormProps,
  PasswordResetFormProps,
  MFASetupProps,
  UserProfileProps,
  OrganizationSwitcherProps,
  SessionListProps,
  
  // UI props
  ButtonProps,
  InputProps,
  AlertProps,
  SpinnerProps,
  SocialButtonProps,
  SocialButtonsProps,
  
  // Hook return types
  UseAuthReturn,
  UseUserReturn,
  UseOrganizationReturn,
  
  // Context types
  VaultAuthProviderProps,
  VaultAuthContextValue,
} from './types';

// Re-export core types from @vault/react
export type {
  User,
  Organization,
  OrganizationMember,
  OrganizationRole,
  Session,
  SessionInfo,
  MfaMethod,
  ApiError,
} from '@vault/react';

// ============================================================================
// Version
// ============================================================================

export const VERSION = '0.1.0';
