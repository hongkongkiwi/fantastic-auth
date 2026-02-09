/**
 * Hosted UI Module
 * 
 * Provides pre-built hosted authentication pages with tenant branding support.
 * 
 * @example
 * ```
 * // Redirect users to the hosted sign-in page
 * window.location.href = 'https://auth.vault.dev/hosted/sign-in?tenant_id=your-tenant';
 * ```
 */

// Types
export type {
  HostedUIConfig,
  OAuthProvider,
  HostedSignInInput,
  HostedSignUpInput,
  HostedAuthResponse,
  HostedOAuthStartInput,
  HostedOAuthCallbackInput,
  HostedPasswordResetInput,
  HostedVerifyEmailInput,
  HostedMfaVerifyInput,
  Organization,
  HostedSwitchOrgInput,
  HostedCreateOrgInput,
  HostedPageSearchParams,
} from './types'

// API functions
export {
  getHostedConfig,
  hostedSignIn,
  hostedSignUp,
  hostedOAuthStart,
  hostedOAuthCallback,
  hostedSendMagicLink,
  hostedRequestPasswordReset,
  hostedVerifyEmail,
  hostedVerifyMfa,
  hostedListOrganizations,
  hostedSwitchOrganization,
  hostedCreateOrganization,
  hostedWebAuthnChallenge,
} from './api'

// Hooks
export {
  HostedConfigProvider,
  useHostedConfig,
  useHostedSearchParams,
} from './useHostedConfig'

// Components
export { HostedLayout, getHostedHeadContent } from './HostedLayout'
