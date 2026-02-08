/**
 * Vault SDK Components
 *
 * Pre-built React components for authentication and user management.
 */

// ============================================================================
// Auth Components
// ============================================================================

export { SignIn } from './SignIn';
export type { SignInProps } from './SignIn';

export { SignUp } from './SignUp';
export type { SignUpProps } from './SignUp';

export { UserButton } from './UserButton';
export type { UserButtonProps } from './UserButton';

export { UserProfile } from './UserProfile';
export type { UserProfileProps } from './UserProfile';

export { WebAuthnButton } from './WebAuthnButton';
export type { WebAuthnButtonProps } from './WebAuthnButton';

export { VerifyEmail } from './VerifyEmail';
export type { VerifyEmailProps } from './VerifyEmail';

export { ResetPassword } from './ResetPassword';
export type { ResetPasswordProps } from './ResetPassword';

export { MFAForm } from './MFAForm';
export type { MFAFormProps } from './MFAForm';

// ============================================================================
// Organization Components
// ============================================================================

export { OrganizationSwitcher } from './OrganizationSwitcher';
export type { OrganizationSwitcherProps, OrganizationSwitcherExtendedProps } from './OrganizationSwitcher';

export { CreateOrganization } from './CreateOrganization';
export type { CreateOrganizationProps } from './CreateOrganization';

export { OrganizationProfile } from './OrganizationProfile';
export type { OrganizationProfileProps } from './OrganizationProfile';

export { OrganizationList } from './OrganizationList';
export type { OrganizationListProps } from './OrganizationList';

// ============================================================================
// Session Components
// ============================================================================

export { SessionManagement } from './SessionManagement';
export type { SessionManagementProps } from './SessionManagement';

// ============================================================================
// Utility Components
// ============================================================================

export { Waitlist } from './Waitlist';
export type { WaitlistProps } from './Waitlist';

export { ImpersonationBanner } from './ImpersonationBanner';
export type { ImpersonationBannerProps } from './ImpersonationBanner';

// ============================================================================
// Control Components
// ============================================================================

export { SignedIn, SignedOut, RequireAuth } from './ControlComponents';
export type { SignedInProps, SignedOutProps, RequireAuthProps } from './ControlComponents';

// ============================================================================
// Route Protection
// ============================================================================

export {
  Protect,
  RedirectToSignIn,
  RedirectToSignUp
} from './Protect';
export type { ProtectProps } from './Protect';

// ============================================================================
// Billing Components
// ============================================================================

export { PricingTable } from './PricingTable';
export type { PricingTableProps } from './PricingTable';

export { CheckoutButton, QuickCheckoutButton } from './CheckoutButton';
export type { CheckoutButtonProps, QuickCheckoutButtonProps } from './CheckoutButton';

export {
  CustomerPortalButton,
  ManageSubscriptionButton,
  UpdatePaymentMethodButton,
  ViewInvoicesButton,
  BillingSettings,
} from './CustomerPortal';
export type {
  CustomerPortalButtonProps,
  BillingSettingsProps,
} from './CustomerPortal';

export {
  SubscriptionStatus,
  UsageMeter,
  InvoiceList,
} from './SubscriptionStatus';
export type {
  SubscriptionStatusProps,
  UsageMeterProps,
  InvoiceListProps,
} from './SubscriptionStatus';

// ============================================================================
// UI Components (Themed)
// ============================================================================

export {
  // Button
  Button,
  // Input
  Input,
  // Card
  Card,
  CardHeader,
  CardContent,
  CardFooter,
  // Divider
  Divider,
  // Header
  Header,
  // SocialButton
  SocialButton,
  SocialButtons,
  // Alert
  Alert,
  // Spinner
  Spinner,
  SpinnerOverlay,
  Skeleton,
} from './ui';

export type {
  // Button
  ButtonProps,
  // Input
  InputProps,
  // Card
  CardProps,
  CardHeaderProps,
  CardContentProps,
  CardFooterProps,
  // Divider
  DividerProps,
  // Header
  HeaderProps,
  // SocialButton
  SocialButtonProps,
  SocialButtonsProps,
  OAuthProvider,
  // Alert
  AlertProps,
  AlertVariant,
  // Spinner
  SpinnerProps,
  SpinnerOverlayProps,
  SkeletonProps,
} from './ui';
