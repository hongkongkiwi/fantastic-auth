/**
 * Hosted UI Configuration Types
 * 
 * These types define the configuration schema for tenant-branded hosted pages.
 */

export interface HostedUIConfig {
  /** Tenant ID this config belongs to */
  tenantId: string
  
  // Branding
  logoUrl?: string
  faviconUrl?: string
  primaryColor?: string
  backgroundColor?: string
  
  // Content
  companyName: string
  signInTitle?: string
  signUpTitle?: string
  
  // Features
  oauthProviders: OAuthProvider[]
  showMagicLink: boolean
  showWebAuthn: boolean
  requireEmailVerification: boolean
  allowSignUp: boolean
  
  // URLs
  afterSignInUrl: string
  afterSignUpUrl: string
  afterSignOutUrl: string
  
  // Legal
  termsUrl?: string
  privacyUrl?: string
  
  // Advanced
  customCss?: string
  customJs?: string
  
  // Security
  allowedRedirectUrls: string[]
}

export type OAuthProvider = 
  | 'google' 
  | 'github' 
  | 'apple' 
  | 'microsoft' 
  | 'slack' 
  | 'discord'

export interface HostedSignInInput {
  email: string
  password: string
  tenantId: string
  mfaCode?: string
}

export interface HostedSignUpInput {
  email: string
  password: string
  name: string
  tenantId: string
}

export interface HostedAuthResponse {
  sessionToken: string
  user: {
    id: string
    email: string
    name?: string
  }
  redirectUrl: string
  requiresMfa?: boolean
  mfaToken?: string
}

export interface HostedOAuthStartInput {
  provider: OAuthProvider
  tenantId: string
  redirectUrl?: string
  state?: string
}

export interface HostedOAuthCallbackInput {
  code: string
  state: string
  tenantId: string
}

export interface HostedPasswordResetInput {
  email: string
  tenantId: string
}

export interface HostedVerifyEmailInput {
  token: string
  tenantId: string
}

export interface HostedMfaVerifyInput {
  code: string
  method: 'totp' | 'email' | 'sms'
  mfaToken: string
  tenantId: string
}

export interface Organization {
  id: string
  name: string
  slug: string
  logoUrl?: string
  role: 'owner' | 'admin' | 'member'
}

export interface HostedSwitchOrgInput {
  organizationId: string
  tenantId: string
}

export interface HostedCreateOrgInput {
  name: string
  slug: string
  tenantId: string
}

// Query parameters for hosted pages
export interface HostedPageSearchParams {
  tenant_id: string
  redirect_url?: string
  oauth_callback?: string
  organization_id?: string
  error?: string
  message?: string
}
