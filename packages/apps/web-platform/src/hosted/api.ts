/**
 * Hosted UI API Functions
 * 
 * These server functions handle hosted authentication operations.
 */

import { createServerFn } from '@tanstack/react-start'
import type {
  HostedUIConfig,
  HostedSignInInput,
  HostedSignUpInput,
  HostedAuthResponse,
  HostedOAuthStartInput,
  HostedOAuthCallbackInput,
  HostedPasswordResetInput,
  HostedVerifyEmailInput,
  HostedMfaVerifyInput,
  HostedSwitchOrgInput,
  HostedCreateOrgInput,
  Organization,
} from './types'
import { env } from '../env/server'

const DEFAULT_BASE_URL = 'http://localhost:8080'

const getBaseUrl = () => (env.INTERNAL_API_BASE_URL || DEFAULT_BASE_URL).replace(/\/+$/, '')
const getClientApiBase = () => `${getBaseUrl()}/api/v1`
const getHostedApiBase = () => `${getBaseUrl()}/hosted/api`

/**
 * Fetch hosted UI configuration for a tenant
 */
export const getHostedConfig = createServerFn({ method: 'GET' })
  .inputValidator((input: { tenantId: string }) => input)
  .handler(async ({ data }): Promise<HostedUIConfig> => {
    const hostedApiBase = getHostedApiBase()

    const response = await fetch(`${hostedApiBase}/config?tenant_id=${encodeURIComponent(data.tenantId)}`)
    if (!response.ok) {
      throw new Error('Failed to load hosted configuration')
    }

    const result = await response.json() as {
      tenant_id: string
      company_name: string
      logo_url?: string
      favicon_url?: string
      primary_color?: string
      background_color?: string
      sign_in_title?: string
      sign_up_title?: string
      oauth_providers: HostedUIConfig['oauthProviders']
      show_magic_link: boolean
      show_web_authn: boolean
      require_email_verification: boolean
      allow_sign_up: boolean
      after_sign_in_url: string
      after_sign_up_url: string
      after_sign_out_url: string
      terms_url?: string
      privacy_url?: string
      custom_css?: string
      custom_js?: string
      allowed_redirect_urls: string[]
    }

    return {
      tenantId: result.tenant_id,
      companyName: result.company_name,
      logoUrl: result.logo_url,
      faviconUrl: result.favicon_url,
      primaryColor: result.primary_color,
      backgroundColor: result.background_color,
      signInTitle: result.sign_in_title,
      signUpTitle: result.sign_up_title,
      oauthProviders: result.oauth_providers,
      showMagicLink: result.show_magic_link,
      showWebAuthn: result.show_web_authn,
      requireEmailVerification: result.require_email_verification,
      allowSignUp: result.allow_sign_up,
      afterSignInUrl: result.after_sign_in_url,
      afterSignUpUrl: result.after_sign_up_url,
      afterSignOutUrl: result.after_sign_out_url,
      termsUrl: result.terms_url,
      privacyUrl: result.privacy_url,
      customCss: result.custom_css,
      customJs: result.custom_js,
      allowedRedirectUrls: result.allowed_redirect_urls,
    }
  })

/**
 * Sign in with email and password
 */
export const hostedSignIn = createServerFn({ method: 'POST' })
  .inputValidator((input: HostedSignInInput & { redirectUrl?: string; mfaCode?: string }) => input)
  .handler(async ({ data }): Promise<HostedAuthResponse> => {
    const hostedApiBase = getHostedApiBase()

    const response = await fetch(`${hostedApiBase}/auth/signin`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: data.email,
        password: data.password,
        tenant_id: data.tenantId,
        mfa_code: data.mfaCode,
        redirect_url: data.redirectUrl,
      }),
    })
    
    if (!response.ok) {
      const error = await response.json().catch(() => ({ message: 'Sign in failed' }))
      throw new Error(error.message || 'Invalid credentials')
    }
    
    const result = await response.json() as {
      session_token: string
      user: HostedAuthResponse['user']
      redirect_url: string
      requires_mfa?: boolean
      mfa_token?: string
    }

    return {
      sessionToken: result.session_token,
      user: result.user,
      redirectUrl: result.redirect_url || data.redirectUrl || '/dashboard',
      requiresMfa: result.requires_mfa,
      mfaToken: result.mfa_token,
    }
  })

/**
 * Sign up with email and password
 */
export const hostedSignUp = createServerFn({ method: 'POST' })
  .inputValidator((input: HostedSignUpInput & { redirectUrl?: string }) => input)
  .handler(async ({ data }): Promise<HostedAuthResponse> => {
    const hostedApiBase = getHostedApiBase()

    const response = await fetch(`${hostedApiBase}/auth/signup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: data.email,
        password: data.password,
        name: data.name,
        tenant_id: data.tenantId,
        redirect_url: data.redirectUrl,
      }),
    })
    
    if (!response.ok) {
      const error = await response.json().catch(() => ({ message: 'Sign up failed' }))
      throw new Error(error.message || 'Could not create account')
    }
    
    const result = await response.json() as {
      session_token: string
      user: HostedAuthResponse['user']
      redirect_url: string
      requires_email_verification?: boolean
    }
    
    return {
      sessionToken: result.session_token || '',
      user: result.user,
      redirectUrl: result.redirect_url || data.redirectUrl || '/welcome',
    }
  })

/**
 * Start OAuth flow
 */
export const hostedOAuthStart = createServerFn({ method: 'POST' })
  .inputValidator((input: HostedOAuthStartInput) => input)
  .handler(async ({ data }): Promise<{ authUrl: string; state: string }> => {
    const hostedApiBase = getHostedApiBase()

    const response = await fetch(`${hostedApiBase}/auth/oauth/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        provider: data.provider,
        tenant_id: data.tenantId,
        redirect_url: data.redirectUrl,
      }),
    })
    
    if (!response.ok) {
      throw new Error('Failed to start OAuth flow')
    }
    
    const result = await response.json() as { auth_url: string; state: string }
    return { authUrl: result.auth_url, state: result.state }
  })

/**
 * Handle OAuth callback
 */
export const hostedOAuthCallback = createServerFn({ method: 'POST' })
  .inputValidator((input: HostedOAuthCallbackInput & { redirectUrl?: string }) => input)
  .handler(async ({ data }): Promise<HostedAuthResponse> => {
    const hostedApiBase = getHostedApiBase()

    const response = await fetch(`${hostedApiBase}/auth/oauth/callback`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        code: data.code,
        state: data.state,
        tenant_id: data.tenantId,
        redirect_url: data.redirectUrl,
      }),
    })
    
    if (!response.ok) {
      const error = await response.json().catch(() => ({ message: 'OAuth failed' }))
      throw new Error(error.message || 'OAuth authentication failed')
    }
    
    const result = await response.json() as {
      session_token: string
      user: HostedAuthResponse['user']
      redirect_url: string
      requires_mfa?: boolean
      mfa_token?: string
    }
    
    return {
      sessionToken: result.session_token,
      user: result.user,
      redirectUrl: result.redirect_url || data.redirectUrl || '/dashboard',
      requiresMfa: result.requires_mfa,
      mfaToken: result.mfa_token,
    }
  })

/**
 * Send magic link
 */
export const hostedSendMagicLink = createServerFn({ method: 'POST' })
  .inputValidator((input: { email: string; tenantId: string; redirectUrl?: string }) => input)
  .handler(async ({ data }): Promise<{ success: boolean }> => {
    const clientApiBase = getClientApiBase()
    
    const response = await fetch(`${clientApiBase}/auth/magic-link`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Tenant-ID': data.tenantId,
      },
      body: JSON.stringify({
        email: data.email,
        redirectUri: data.redirectUrl,
      }),
    })
    
    if (!response.ok) {
      const error = await response.json().catch(() => ({ message: 'Failed to send magic link' }))
      throw new Error(error.message)
    }
    
    return { success: true }
  })

/**
 * Request password reset
 */
export const hostedRequestPasswordReset = createServerFn({ method: 'POST' })
  .inputValidator((input: HostedPasswordResetInput) => input)
  .handler(async ({ data }): Promise<{ success: boolean }> => {
    const hostedApiBase = getHostedApiBase()

    const response = await fetch(`${hostedApiBase}/auth/password-reset`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: data.email,
        tenant_id: data.tenantId,
      }),
    })
    
    if (!response.ok) {
      const error = await response.json().catch(() => ({ message: 'Failed to send reset email' }))
      throw new Error(error.message)
    }
    
    return { success: true }
  })

/**
 * Verify email
 */
export const hostedVerifyEmail = createServerFn({ method: 'POST' })
  .inputValidator((input: HostedVerifyEmailInput) => input)
  .handler(async ({ data }): Promise<{ success: boolean; redirectUrl: string }> => {
    const clientApiBase = getClientApiBase()
    
    const response = await fetch(`${clientApiBase}/auth/verify-email`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Tenant-ID': data.tenantId,
      },
      body: JSON.stringify({
        token: data.token,
      }),
    })
    
    if (!response.ok) {
      const error = await response.json().catch(() => ({ message: 'Invalid or expired token' }))
      throw new Error(error.message)
    }
    
    return { success: true, redirectUrl: '/hosted/sign-in' }
  })

/**
 * Verify MFA code
 */
export const hostedVerifyMfa = createServerFn({ method: 'POST' })
  .inputValidator((input: HostedMfaVerifyInput & { redirectUrl?: string }) => input)
  .handler(async (): Promise<HostedAuthResponse> => {
    throw new Error('Hosted MFA token verification is not available in this build')
  })

/**
 * List user's organizations
 */
export const hostedListOrganizations = createServerFn({ method: 'GET' })
  .inputValidator((input: { tenantId: string; sessionToken: string }) => input)
  .handler(async ({ data }): Promise<{ organizations: Organization[] }> => {
    const clientApiBase = getClientApiBase()
    
    const response = await fetch(`${clientApiBase}/organizations`, {
      headers: {
        'Authorization': `Bearer ${data.sessionToken}`,
        'X-Tenant-ID': data.tenantId,
      },
    })
    
    if (!response.ok) {
      throw new Error('Failed to fetch organizations')
    }
    
    return response.json()
  })

/**
 * Switch organization
 */
export const hostedSwitchOrganization = createServerFn({ method: 'POST' })
  .inputValidator((input: HostedSwitchOrgInput & { sessionToken: string }) => input)
  .handler(async ({ data }): Promise<{ success: boolean; redirectUrl: string }> => {
    const clientApiBase = getClientApiBase()
    
    const response = await fetch(`${clientApiBase}/organizations/switch`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${data.sessionToken}`,
        'X-Tenant-ID': data.tenantId,
      },
      body: JSON.stringify({
        organization_id: data.organizationId,
      }),
    })
    
    if (!response.ok) {
      throw new Error('Failed to switch organization')
    }
    
    return { success: true, redirectUrl: '/dashboard' }
  })

/**
 * Create organization
 */
export const hostedCreateOrganization = createServerFn({ method: 'POST' })
  .inputValidator((input: HostedCreateOrgInput & { sessionToken: string }) => input)
  .handler(async ({ data }): Promise<Organization> => {
    const clientApiBase = getClientApiBase()
    
    const response = await fetch(`${clientApiBase}/organizations`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${data.sessionToken}`,
        'X-Tenant-ID': data.tenantId,
      },
      body: JSON.stringify({
        name: data.name,
        slug: data.slug,
      }),
    })
    
    if (!response.ok) {
      const error = await response.json().catch(() => ({ message: 'Failed to create organization' }))
      throw new Error(error.message)
    }
    
    return response.json()
  })

/**
 * Generate WebAuthn challenge for passkey sign-in
 */
export const hostedWebAuthnChallenge = createServerFn({ method: 'POST' })
  .inputValidator((input: { tenantId: string }) => input)
  .handler(async ({ data }): Promise<{ challenge: string; options: {} }> => {
    const clientApiBase = getClientApiBase()
    
    const response = await fetch(`${clientApiBase}/auth/webauthn/authenticate/begin`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Tenant-ID': data.tenantId,
      },
      body: JSON.stringify({}),
    })
    
    if (!response.ok) {
      throw new Error('Failed to generate WebAuthn challenge')
    }
    
    return response.json() as Promise<{ challenge: string; options: {} }>
  })
