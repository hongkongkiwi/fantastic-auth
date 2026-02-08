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
import { createSession, getSessionCookieName, getSessionTtlSeconds } from '../server/session'

const DEFAULT_BASE_URL = 'http://localhost:8080/api/v1'

const getBaseUrl = () => env.INTERNAL_API_BASE_URL || DEFAULT_BASE_URL

/**
 * Fetch hosted UI configuration for a tenant
 */
export const getHostedConfig = createServerFn({ method: 'GET' })
  .inputValidator((input: { tenantId: string }) => input)
  .handler(async ({ data }): Promise<HostedUIConfig> => {
    const baseUrl = getBaseUrl()
    
    // In production, this would fetch from the vault-server API
    // For now, we return a mock config based on tenant
    const response = await fetch(`${baseUrl}/hosted/config?tenant_id=${data.tenantId}`)
    
    if (response.ok) {
      return response.json() as Promise<HostedUIConfig>
    }
    
    // Fallback mock config for development
    return {
      tenantId: data.tenantId,
      companyName: 'Vault',
      signInTitle: 'Sign in to your account',
      signUpTitle: 'Create your account',
      oauthProviders: ['google', 'github'],
      showMagicLink: true,
      showWebAuthn: true,
      requireEmailVerification: true,
      allowSignUp: true,
      afterSignInUrl: '/dashboard',
      afterSignUpUrl: '/welcome',
      afterSignOutUrl: '/hosted/sign-in',
      allowedRedirectUrls: ['http://localhost:3000', 'http://localhost:8080'],
      termsUrl: '/terms',
      privacyUrl: '/privacy',
    }
  })

/**
 * Sign in with email and password
 */
export const hostedSignIn = createServerFn({ method: 'POST' })
  .inputValidator((input: HostedSignInInput & { redirectUrl?: string }) => input)
  .handler(async ({ data }): Promise<HostedAuthResponse> => {
    const baseUrl = getBaseUrl()
    
    const response = await fetch(`${baseUrl}/auth/signin`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: data.email,
        password: data.password,
        tenant_id: data.tenantId,
      }),
    })
    
    if (!response.ok) {
      const error = await response.json().catch(() => ({ message: 'Sign in failed' }))
      throw new Error(error.message || 'Invalid credentials')
    }
    
    const result = await response.json()
    
    // Create session cookie
    const session = createSession()
    const isProduction = process.env.NODE_ENV === 'production'
    const cookieParts = [
      `${getSessionCookieName()}_hosted=${encodeURIComponent(session.token)}`,
      `Max-Age=${getSessionTtlSeconds()}`,
      'Path=/',
      'SameSite=Lax',
      'HttpOnly',
    ]
    if (isProduction) {
      cookieParts.push('Secure')
    }
    
    // Return with Set-Cookie header handled by response
    return {
      sessionToken: session.token,
      user: result.user,
      redirectUrl: data.redirectUrl || '/dashboard',
      requiresMfa: result.requiresMfa,
      mfaToken: result.mfaToken,
    }
  })

/**
 * Sign up with email and password
 */
export const hostedSignUp = createServerFn({ method: 'POST' })
  .inputValidator((input: HostedSignUpInput & { redirectUrl?: string }) => input)
  .handler(async ({ data }): Promise<HostedAuthResponse> => {
    const baseUrl = getBaseUrl()
    
    const response = await fetch(`${baseUrl}/auth/signup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: data.email,
        password: data.password,
        name: data.name,
        tenant_id: data.tenantId,
      }),
    })
    
    if (!response.ok) {
      const error = await response.json().catch(() => ({ message: 'Sign up failed' }))
      throw new Error(error.message || 'Could not create account')
    }
    
    const result = await response.json()
    
    return {
      sessionToken: result.sessionToken || '',
      user: result.user,
      redirectUrl: data.redirectUrl || '/welcome',
    }
  })

/**
 * Start OAuth flow
 */
export const hostedOAuthStart = createServerFn({ method: 'POST' })
  .inputValidator((input: HostedOAuthStartInput) => input)
  .handler(async ({ data }): Promise<{ authUrl: string; state: string }> => {
    const baseUrl = getBaseUrl()
    
    const response = await fetch(`${baseUrl}/auth/oauth/${data.provider}/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tenant_id: data.tenantId,
        redirect_uri: `${baseUrl}/hosted/oauth-callback`,
        state: data.state,
      }),
    })
    
    if (!response.ok) {
      throw new Error('Failed to start OAuth flow')
    }
    
    return response.json()
  })

/**
 * Handle OAuth callback
 */
export const hostedOAuthCallback = createServerFn({ method: 'POST' })
  .inputValidator((input: HostedOAuthCallbackInput & { redirectUrl?: string }) => input)
  .handler(async ({ data }): Promise<HostedAuthResponse> => {
    const baseUrl = getBaseUrl()
    
    const response = await fetch(`${baseUrl}/auth/oauth/callback`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        code: data.code,
        state: data.state,
        tenant_id: data.tenantId,
      }),
    })
    
    if (!response.ok) {
      const error = await response.json().catch(() => ({ message: 'OAuth failed' }))
      throw new Error(error.message || 'OAuth authentication failed')
    }
    
    const result = await response.json()
    
    return {
      sessionToken: result.sessionToken,
      user: result.user,
      redirectUrl: data.redirectUrl || '/dashboard',
    }
  })

/**
 * Send magic link
 */
export const hostedSendMagicLink = createServerFn({ method: 'POST' })
  .inputValidator((input: { email: string; tenantId: string; redirectUrl?: string }) => input)
  .handler(async ({ data }): Promise<{ success: boolean }> => {
    const baseUrl = getBaseUrl()
    
    const response = await fetch(`${baseUrl}/auth/magic-link`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: data.email,
        tenant_id: data.tenantId,
        redirect_url: data.redirectUrl,
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
    const baseUrl = getBaseUrl()
    
    const response = await fetch(`${baseUrl}/auth/password-reset-request`, {
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
    const baseUrl = getBaseUrl()
    
    const response = await fetch(`${baseUrl}/auth/verify-email`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        token: data.token,
        tenant_id: data.tenantId,
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
  .handler(async ({ data }): Promise<HostedAuthResponse> => {
    const baseUrl = getBaseUrl()
    
    const response = await fetch(`${baseUrl}/auth/mfa/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        code: data.code,
        method: data.method,
        mfa_token: data.mfaToken,
        tenant_id: data.tenantId,
      }),
    })
    
    if (!response.ok) {
      const error = await response.json().catch(() => ({ message: 'Invalid MFA code' }))
      throw new Error(error.message)
    }
    
    const result = await response.json()
    
    return {
      sessionToken: result.sessionToken,
      user: result.user,
      redirectUrl: data.redirectUrl || '/dashboard',
    }
  })

/**
 * List user's organizations
 */
export const hostedListOrganizations = createServerFn({ method: 'GET' })
  .inputValidator((input: { tenantId: string; sessionToken: string }) => input)
  .handler(async ({ data }): Promise<{ organizations: Organization[] }> => {
    const baseUrl = getBaseUrl()
    
    const response = await fetch(`${baseUrl}/organizations`, {
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
    const baseUrl = getBaseUrl()
    
    const response = await fetch(`${baseUrl}/organizations/switch`, {
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
    const baseUrl = getBaseUrl()
    
    const response = await fetch(`${baseUrl}/organizations`, {
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
    const baseUrl = getBaseUrl()
    
    const response = await fetch(`${baseUrl}/auth/webauthn/challenge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tenant_id: data.tenantId,
      }),
    })
    
    if (!response.ok) {
      throw new Error('Failed to generate WebAuthn challenge')
    }
    
    return response.json() as Promise<{ challenge: string; options: {} }>
  })
