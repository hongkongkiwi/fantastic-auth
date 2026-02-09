/**
 * Core types for @vault/nextjs
 */

import type { User, Session } from '@vault/react';

export type { User, Session };

/**
 * Auth result from server-side auth check
 */
export interface AuthResult {
  /** The user's ID if authenticated, null otherwise */
  userId: string | null;
  /** The current session if authenticated, null otherwise */
  session: Session | null;
  /** The organization ID if the user is part of one, null otherwise */
  orgId: string | null;
  /** The organization role if applicable */
  orgRole: string | null;
  /** Whether the user is signed in */
  isSignedIn: boolean;
}

/**
 * Options for the auth middleware
 */
export interface AuthMiddlewareOptions {
  /**
   * Routes that are publicly accessible without authentication.
   * Supports glob patterns like '/sign-in', '/api/webhooks/*'
   */
  publicRoutes?: string[];
  /**
   * Routes that require authentication. If specified, all other routes are public.
   * Cannot be used with publicRoutes.
   */
  protectedRoutes?: string[];
  /**
   * API routes that should be publicly accessible.
   */
  apiRoutes?: string[];
  /**
   * URL to redirect to when authentication is required.
   * Defaults to '/sign-in'
   */
  signInUrl?: string;
  /**
   * URL to redirect to after sign in.
   * Defaults to the originally requested URL
   */
  afterSignInUrl?: string;
  /**
   * Whether to enable debug logging
   */
  debug?: boolean;
  /**
   * Custom handler for unauthorized requests
   */
  unauthorizedHandler?: (req: Request) => Response | Promise<Response>;
}

/**
 * Configuration for VaultProvider
 */
export interface VaultProviderConfig {
  /** The Vault API URL */
  apiUrl: string;
  /** The tenant ID */
  tenantId: string;
  /** Optional publishable key for client-side operations */
  publishableKey?: string;
  /** Whether to enable debug logging */
  debug?: boolean;
  /** Session token lifetime in seconds */
  sessionLifetime?: number;
}

/**
 * Token validation result
 */
export interface TokenValidationResult {
  valid: boolean;
  userId?: string;
  sessionId?: string;
  orgId?: string;
  orgRole?: string;
  expiresAt?: number;
  error?: string;
}

/**
 * Cookie configuration
 */
export interface CookieConfig {
  /** Cookie name for the session token */
  sessionCookieName: string;
  /** Cookie name for the refresh token */
  refreshCookieName: string;
  /** Cookie domain */
  domain?: string;
  /** Whether the cookie is secure (HTTPS only) */
  secure: boolean;
  /** SameSite attribute */
  sameSite: 'strict' | 'lax' | 'none';
  /** Cookie path */
  path: string;
  /** Cookie max age in seconds */
  maxAge: number;
}

/**
 * Server-side auth context
 */
export interface ServerAuthContext {
  auth: () => Promise<AuthResult>;
  currentUser: () => Promise<User | null>;
  getToken: () => Promise<string | null>;
}

/**
 * Route handler context
 */
export interface RouteHandlerContext {
  auth: AuthResult;
  user: User | null;
  token: string | null;
}

/**
 * Options for route handlers
 */
export interface RouteHandlerOptions {
  /**
   * Whether to require authentication for this route
   * @default true
   */
  requireAuth?: boolean;
  /**
   * Custom unauthorized response handler
   */
  onUnauthorized?: () => Response;
}

/**
 * JWT claims from Vault session token
 */
export interface VaultJwtClaims {
  sub: string;
  sid: string;
  tid: string;
  org_id?: string;
  org_role?: string;
  iat: number;
  exp: number;
  iss: string;
  aud: string;
}

/**
 * API error response
 */
export interface ApiError {
  code: string;
  message: string;
  details?: Record<string, unknown>;
}

/**
 * Auth state for client-side
 */
export interface AuthState {
  isLoaded: boolean;
  isSignedIn: boolean;
  user: User | null;
  session: Session | null;
  orgId: string | null;
  orgRole: string | null;
}
