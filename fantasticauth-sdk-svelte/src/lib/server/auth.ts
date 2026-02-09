/**
 * Server Auth
 * 
 * Server-side authentication utilities for SvelteKit.
 */

import { redirect, type Handle, type ServerLoad } from '@sveltejs/kit';
import type { VaultAuthConfig, User, Session } from '../types.js';

/**
 * Validate session token with Vault API
 */
async function validateSession(
  token: string,
  config: VaultAuthConfig
): Promise<{ user: User; session: Session } | null> {
  try {
    const response = await fetch(`${config.apiUrl}/api/v1/auth/session`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'X-Tenant-ID': config.tenantId,
      }
    });
    
    if (!response.ok) {
      return null;
    }
    
    const session = await response.json();
    return {
      user: session.user,
      session: {
        ...session,
        accessToken: token,
      }
    };
  } catch {
    return null;
  }
}

/**
 * Get token from request (cookie or header)
 */
function getTokenFromRequest(request: Request): string | null {
  // Check Authorization header
  const authHeader = request.headers.get('Authorization');
  if (authHeader?.startsWith('Bearer ')) {
    return authHeader.slice(7);
  }
  
  // Check cookie
  const cookie = request.headers.get('cookie');
  if (cookie) {
    const match = cookie.match(/vault_session_token=([^;]+)/);
    if (match) {
      return decodeURIComponent(match[1]);
    }
  }
  
  return null;
}

/**
 * Check if route is public
 */
function isPublicRoute(pathname: string, publicRoutes: string[]): boolean {
  return publicRoutes.some(route => {
    if (route.endsWith('*')) {
      return pathname.startsWith(route.slice(0, -1));
    }
    return pathname === route || pathname.startsWith(`${route}/`);
  });
}

/**
 * Vault auth handle for SvelteKit
 * 
 * @example
 * ```typescript
 * // hooks.server.ts
 * import { vaultAuth } from '@vault/svelte/server';
 * 
 * export const handle = vaultAuth({
 *   publicRoutes: ['/sign-in', '/sign-up', '/api/webhook'],
 *   apiUrl: 'https://api.vault.dev',
 *   tenantId: 'my-tenant',
 *   signInUrl: '/sign-in'
 * });
 * ```
 */
export function vaultAuth(config: VaultAuthConfig): Handle {
  return async ({ event, resolve }) => {
    const { request, url } = event;
    
    // Get token from request
    const token = getTokenFromRequest(request);
    
    // Validate session if token exists
    if (token) {
      const result = await validateSession(token, config);
      if (result) {
        event.locals.user = result.user;
        event.locals.session = result.session;
        event.locals.token = token;
      } else {
        event.locals.user = null;
        event.locals.session = null;
        event.locals.token = null;
      }
    } else {
      event.locals.user = null;
      event.locals.session = null;
      event.locals.token = null;
    }
    
    // Check if route requires auth
    const isPublic = isPublicRoute(url.pathname, config.publicRoutes || []);
    const isProtected = config.protectedRoutes 
      ? config.protectedRoutes.some(route => url.pathname.startsWith(route))
      : !isPublic;
    
    if (isProtected && !event.locals.user) {
      // Redirect to sign in
      const signInUrl = config.signInUrl || '/sign-in';
      const redirectUrl = encodeURIComponent(url.pathname + url.search);
      throw redirect(302, `${signInUrl}?redirect=${redirectUrl}`);
    }
    
    return resolve(event);
  };
}

/**
 * Require auth for a server load function
 * 
 * @example
 * ```typescript
 * // +page.server.ts
 * import { requireAuth } from '@vault/svelte/server';
 * 
 * export const load = requireAuth(async ({ locals }) => {
 *   // locals.user is guaranteed to be set
 *   return {
 *     user: locals.user
 *   };
 * });
 * ```
 */
export function requireAuth<T extends Record<string, any>>(
  loadFn: (event: Parameters<ServerLoad>[0]) => Promise<T> | T
): ServerLoad {
  return async (event) => {
    if (!event.locals.user) {
      throw redirect(302, '/sign-in');
    }
    
    return loadFn(event);
  };
}

/**
 * Optional auth for a server load function
 * Makes user available if authenticated, but doesn't require it
 * 
 * @example
 * ```typescript
 * // +page.server.ts
 * import { optionalAuth } from '@vault/svelte/server';
 * 
 * export const load = optionalAuth(async ({ locals }) => {
 *   return {
 *     user: locals.user // may be null
 *   };
 * });
 * ```
 */
export function optionalAuth<T extends Record<string, any>>(
  loadFn: (event: Parameters<ServerLoad>[0]) => Promise<T> | T
): ServerLoad {
  return async (event) => {
    return loadFn(event);
  };
}
