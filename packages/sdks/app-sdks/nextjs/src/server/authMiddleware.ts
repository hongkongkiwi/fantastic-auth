/**
 * Edge middleware for Vault authentication
 * 
 * Works in Next.js middleware.ts with Edge runtime
 * 
 * @example
 * ```tsx
 * // middleware.ts
 * import { authMiddleware } from '@fantasticauth/nextjs/server';
 * 
 * export default authMiddleware({
 *   publicRoutes: ['/sign-in', '/sign-up', '/'],
 *   apiRoutes: ['/api/webhooks'],
 * });
 * 
 * export const config = {
 *   matcher: ['/((?!_next|.*\\..*).*)'],
 * };
 * ```
 */

import { NextResponse, type NextRequest } from 'next/server';
import type { AuthMiddlewareOptions, TokenValidationResult } from '../types';
import { verifyToken, createAuthClient } from './authClient';

// Cookie names
const SESSION_COOKIE_NAME = '__fantasticauth_session';
const REFRESH_COOKIE_NAME = '__fantasticauth_refresh';
const LEGACY_SESSION_COOKIE_NAME = '__vault_session';
const LEGACY_REFRESH_COOKIE_NAME = '__vault_refresh';

// Default configuration
const DEFAULT_OPTIONS: Required<Omit<AuthMiddlewareOptions, 'publicRoutes' | 'protectedRoutes' | 'apiRoutes' | 'unauthorizedHandler'>> = {
  signInUrl: '/sign-in',
  afterSignInUrl: '/',
  debug: false,
};

/**
 * Get environment configuration for Edge runtime
 */
function getEdgeConfig() {
  const apiUrl = process.env.VAULT_API_URL;
  const tenantId = process.env.VAULT_TENANT_ID;
  const secretKey = process.env.VAULT_SECRET_KEY;

  if (!apiUrl) {
    throw new Error('VAULT_API_URL environment variable is not set');
  }

  if (!tenantId) {
    throw new Error('VAULT_TENANT_ID environment variable is not set');
  }

  return { apiUrl, tenantId, secretKey };
}

function getApiBase(apiUrl: string): string {
  const normalized = apiUrl.replace(/\/$/, '');
  return normalized.endsWith('/api') ? normalized : `${normalized}/api`;
}

/**
 * Check if a path matches any of the patterns
 * Supports wildcards: * matches any single path segment, ** matches any number of segments
 */
function matchesPath(path: string, patterns: string[]): boolean {
  return patterns.some((pattern) => {
    // Exact match
    if (pattern === path) {
      return true;
    }

    // Convert glob pattern to regex
    const regexPattern = pattern
      .replace(/\*\*/g, '{{GLOBSTAR}}')
      .replace(/\*/g, '[^/]*')
      .replace(/\{\{GLOBSTAR\}\}/g, '.*');

    const regex = new RegExp(`^${regexPattern}$`);
    return regex.test(path);
  });
}

/**
 * Validate session token in Edge runtime
 */
async function validateSessionInEdge(
  token: string,
  apiUrl: string,
  tenantId: string,
  secretKey?: string
): Promise<TokenValidationResult> {
  if (secretKey) {
    // Verify JWT signature with configured key.
    return verifyToken(token, secretKey);
  }

  // Fall back to server-side session validation when no verification key is available.
  const authClient = createAuthClient(apiUrl, tenantId);
  return authClient.validateSession(token);
}

/**
 * Create redirect URL with return path
 */
function createRedirectUrl(
  baseUrl: string,
  returnUrl: string,
  signInUrl: string
): string {
  const url = new URL(signInUrl, baseUrl);
  url.searchParams.set('redirect_url', returnUrl);
  return url.toString();
}

/**
 * Create a debug logger
 */
function createLogger(debug: boolean) {
  return {
    log: (...args: unknown[]) => {
      if (debug) {
        console.log('[Vault Middleware]', ...args);
      }
    },
    error: (...args: unknown[]) => {
      if (debug) {
        console.error('[Vault Middleware]', ...args);
      }
    },
  };
}

/**
 * Authentication middleware for Next.js Edge runtime
 * 
 * @param options - Configuration options
 * @returns Next.js middleware function
 * 
 * @example
 * ```tsx
 * // middleware.ts
 * import { authMiddleware } from '@fantasticauth/nextjs/server';
 * 
 * export default authMiddleware({
 *   publicRoutes: [
 *     '/',
 *     '/sign-in',
 *     '/sign-up',
 *     '/forgot-password',
 *     '/reset-password',
 *     '/api/webhooks/(.*)',
 *   ],
 *   signInUrl: '/sign-in',
 * });
 * 
 * export const config = {
 *   matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
 * };
 * ```
 */
export function authMiddleware(options: AuthMiddlewareOptions = {}) {
  const config = { ...DEFAULT_OPTIONS, ...options };
  const logger = createLogger(config.debug);

  return async function middleware(request: NextRequest) {
    const { pathname, search } = request.nextUrl;
    const url = request.url;

    logger.log('Processing request:', pathname);

    // Determine if this is an API route
    const isApiRoute = pathname.startsWith('/api/');

    // Check if the route is explicitly public
    const publicRoutes = config.publicRoutes || [];
    const isPublicRoute = matchesPath(pathname, publicRoutes);

    // Check if the route is explicitly protected
    const protectedRoutes = config.protectedRoutes || [];
    const isProtectedRoute = protectedRoutes.length > 0 
      ? matchesPath(pathname, protectedRoutes)
      : !isPublicRoute;

    // Check if this is a public API route
    const apiRoutes = config.apiRoutes || [];
    const isPublicApiRoute = isApiRoute && matchesPath(pathname, apiRoutes);

    logger.log('Route status:', {
      isPublicRoute,
      isProtectedRoute,
      isApiRoute,
      isPublicApiRoute,
    });

    // Allow public routes without authentication
    if (isPublicRoute || isPublicApiRoute) {
      logger.log('Allowing public route');
      return NextResponse.next();
    }

    // Skip auth check if protectedRoutes is set and this route is not in it
    if (protectedRoutes.length > 0 && !isProtectedRoute) {
      logger.log('Route not in protectedRoutes, allowing');
      return NextResponse.next();
    }

    // Get session token from cookies
    const sessionToken =
      request.cookies.get(SESSION_COOKIE_NAME)?.value ||
      request.cookies.get(LEGACY_SESSION_COOKIE_NAME)?.value;
    const refreshToken =
      request.cookies.get(REFRESH_COOKIE_NAME)?.value ||
      request.cookies.get(LEGACY_REFRESH_COOKIE_NAME)?.value;

    logger.log('Session token present:', !!sessionToken);

    // Validate session
    let isAuthenticated = false;
    let validationResult: TokenValidationResult | null = null;

    if (sessionToken) {
      try {
        const { apiUrl, tenantId, secretKey } = getEdgeConfig();
        validationResult = await validateSessionInEdge(sessionToken, apiUrl, tenantId, secretKey);
        isAuthenticated = validationResult.valid;
      } catch (error) {
        logger.error('Session validation error:', error);
        isAuthenticated = false;
      }
    }

    logger.log('Authentication status:', isAuthenticated);

    // Handle authenticated user
    if (isAuthenticated) {
      // Check if user is on sign-in page (redirect to afterSignInUrl)
      if (pathname === config.signInUrl || pathname.startsWith('/sign-')) {
        const redirectUrl = request.nextUrl.searchParams.get('redirect_url') || config.afterSignInUrl;
        logger.log('Authenticated user on sign-in page, redirecting to:', redirectUrl);
        return NextResponse.redirect(new URL(redirectUrl, url));
      }

      // Add user info to headers for downstream use
      const response = NextResponse.next();
      if (validationResult?.userId) {
        response.headers.set('x-vault-user-id', validationResult.userId);
      }
      if (validationResult?.orgId) {
        response.headers.set('x-vault-org-id', validationResult.orgId);
      }
      if (validationResult?.orgRole) {
        response.headers.set('x-vault-org-role', validationResult.orgRole);
      }

      return response;
    }

    // Handle unauthenticated user
    // Try to refresh the session if we have a refresh token
    if (refreshToken && !isAuthenticated) {
      try {
        const { apiUrl, tenantId } = getEdgeConfig();
        const refreshResponse = await fetch(`${getApiBase(apiUrl)}/v1/auth/refresh`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Tenant-ID': tenantId,
          },
          body: JSON.stringify({ refreshToken }),
        });

        if (refreshResponse.ok) {
          const data = await refreshResponse.json();
          
          // Set new cookies and continue
          const response = NextResponse.next();
          response.cookies.set(SESSION_COOKIE_NAME, data.token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            path: '/',
            maxAge: 60 * 60 * 24 * 7, // 7 days
          });
          if (data.refreshToken) {
            response.cookies.set(REFRESH_COOKIE_NAME, data.refreshToken, {
              httpOnly: true,
              secure: process.env.NODE_ENV === 'production',
              sameSite: 'lax',
              path: '/',
              maxAge: 60 * 60 * 24 * 30, // 30 days
            });
          }
          response.cookies.delete(LEGACY_SESSION_COOKIE_NAME);
          response.cookies.delete(LEGACY_REFRESH_COOKIE_NAME);

          // Add user info to headers
          if (data.userId) {
            response.headers.set('x-vault-user-id', data.userId);
          }

          logger.log('Session refreshed successfully');
          return response;
        }
      } catch (error) {
        logger.error('Token refresh error:', error);
      }
    }

    // User needs to authenticate
    if (isApiRoute) {
      // For API routes, return 401
      if (config.unauthorizedHandler) {
        return config.unauthorizedHandler(request);
      }

      return new NextResponse(
        JSON.stringify({
          error: 'Unauthorized',
          code: 'authentication_required',
        }),
        {
          status: 401,
          headers: {
            'Content-Type': 'application/json',
            'WWW-Authenticate': 'Bearer',
          },
        }
      );
    }

    // For page routes, redirect to sign-in
    const returnUrl = `${pathname}${search}`;
    const redirectUrl = createRedirectUrl(url, returnUrl, config.signInUrl);
    
    logger.log('Redirecting to sign-in:', redirectUrl);
    return NextResponse.redirect(redirectUrl);
  };
}

/**
 * Create a custom middleware with additional logic
 * 
 * @param handler - Custom handler function
 * @returns Next.js middleware function
 * 
 * @example
 * ```tsx
 * // middleware.ts
 * import { createMiddleware } from '@fantasticauth/nextjs/server';
 * 
 * export default createMiddleware(async (request, auth) => {
 *   // Custom logic here
 *   if (auth.userId && request.nextUrl.pathname.startsWith('/admin')) {
 *     // Check admin permissions
 *   }
 *   
 *   return undefined; // Continue to next middleware
 * });
 * ```
 */
export function createMiddleware(
  handler: (
    request: NextRequest,
    auth: { userId: string | null; orgId: string | null; orgRole: string | null }
  ) => NextResponse | Promise<NextResponse | undefined> | undefined
) {
  return async function middleware(request: NextRequest): Promise<NextResponse> {
    const sessionToken =
      request.cookies.get(SESSION_COOKIE_NAME)?.value ||
      request.cookies.get(LEGACY_SESSION_COOKIE_NAME)?.value;
    let auth = { userId: null as string | null, orgId: null as string | null, orgRole: null as string | null };

    if (sessionToken) {
      try {
        const { apiUrl, tenantId, secretKey } = getEdgeConfig();
        const validation = await validateSessionInEdge(sessionToken, apiUrl, tenantId, secretKey);
        if (validation.valid) {
          auth = {
            userId: validation.userId ?? null,
            orgId: validation.orgId ?? null,
            orgRole: validation.orgRole ?? null,
          };
        }
      } catch {
        auth = { userId: null, orgId: null, orgRole: null };
      }
    }

    const result = await handler(request, auth);
    
    if (result) {
      return result;
    }

    return NextResponse.next();
  };
}
