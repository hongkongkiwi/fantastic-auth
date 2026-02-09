/**
 * Authentication API Module
 * 
 * SECURITY NOTE: This application uses httpOnly cookies for session management.
 * All requests automatically include credentials via credentials: 'include'.
 * The browser handles sending the httpOnly cookie; we never access it in JavaScript.
 */

import { notifyAuthUnauthorized } from './storage'
import { env } from '@/env/client'
import { appLogger } from '@/lib/logger'

export type AuthUser = {
  id: string
  email: string
  firstName?: string
  lastName?: string
  displayName?: string
  phone?: string
  avatarUrl?: string
  emailVerified?: boolean
  createdAt?: string
  lastLoginAt?: string
}

const API_BASE_URL = env.VITE_API_URL || '/api/v1'

export class AuthMfaRequiredError extends Error {
  code = 'MFA_REQUIRED'
  mfaToken?: string
  constructor(message: string, mfaToken?: string) {
    super(message)
    this.name = 'AuthMfaRequiredError'
    this.mfaToken = mfaToken
  }
}

type RequestOptions = {
  method?: string
  body?: unknown
}

type AuthPayload = {
  token?: string
  accessToken?: string
  jwt?: string
  user?: AuthUser
  data?: {
    token?: string
    accessToken?: string
    user?: AuthUser
  }
  mfaRequired?: boolean
  mfaToken?: string
  requires_mfa?: boolean
  mfa_token?: string
}

const extractMessage = (payload: unknown, fallback: string): string => {
  if (!payload || typeof payload !== 'object') return fallback
  const maybeMessage = (payload as { message?: unknown }).message
  if (typeof maybeMessage === 'string' && maybeMessage.trim()) return maybeMessage
  return fallback
}

const request = async <T>(path: string, options: RequestOptions = {}): Promise<T> => {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  }

  const response = await fetch(`${API_BASE_URL}${path}`, {
    method: options.method || 'GET',
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined,
    credentials: 'include', // Required for httpOnly cookies to be sent/received
  })

  const raw = await response.text()
  const payload = raw
    ? (() => {
        try {
          return JSON.parse(raw) as unknown
        } catch {
          return { message: raw }
        }
      })()
    : null

  if (!response.ok) {
    if (response.status === 401) {
      notifyAuthUnauthorized()
      appLogger.warn('Auth API unauthorized response', { path, status: response.status })
    }
    throw new Error(extractMessage(payload, `Request failed with status ${response.status}`))
  }

  return payload as T
}

const getTokenFromPayload = (payload: AuthPayload): string | null =>
  payload.token || payload.accessToken || payload.jwt || payload.data?.token || payload.data?.accessToken || null

const getUserFromPayload = (payload: AuthPayload): AuthUser | null =>
  payload.user || payload.data?.user || null

export const authApi = {
  async login(email: string, password: string, mfaCode?: string, mfaToken?: string) {
    const payload = await request<AuthPayload>('/auth/login', {
      method: 'POST',
      body: { email, password, mfaCode, mfaToken },
    })
    const requiresMfa = Boolean(payload.mfaRequired || payload.requires_mfa)
    const resolvedMfaToken = payload.mfaToken || payload.mfa_token
    if (requiresMfa) {
      throw new AuthMfaRequiredError(
        'Multi-factor authentication code required.',
        resolvedMfaToken,
      )
    }

    const token = getTokenFromPayload(payload)
    const user = getUserFromPayload(payload)
    if (!token || !user) {
      throw new Error('Login response did not include a token and user profile.')
    }
    return { token, user }
  },

  async getOAuthRedirect(provider: 'google' | 'github' | 'microsoft' | 'apple', redirectUri: string) {
    return request<{ authUrl?: string; authorizationUrl?: string }>(`/auth/oauth/${provider}`, {
      method: 'POST',
      body: { redirectUri },
    })
  },

  async logout() {
    await request('/auth/logout', {
      method: 'POST',
    })
  },

  async getMe() {
    return request<AuthUser>('/users/me', {})
  },

  async updateMe(data: Partial<AuthUser>) {
    return request<AuthUser>('/users/me', {
      method: 'PATCH',
      body: data,
    })
  },

  async changePassword(currentPassword: string, newPassword: string) {
    return request<{ message: string }>('/users/me/password', {
      method: 'POST',
      body: { currentPassword, newPassword },
    })
  },
}
