/**
 * Server-side authentication utilities for Next.js App Router
 * 
 * These functions are designed to work in:
 * - Server Components
 * - Server Actions
 * - Route Handlers
 * 
 * They use the `cookies()` function from `next/headers` to access session cookies.
 */

import { cookies } from 'next/headers';
import { cache } from 'react';
import type { AuthResult, User, TokenValidationResult } from '../types';
import { verifyToken, createAuthClient } from './authClient';

// Session cookie name
const SESSION_COOKIE_NAME = '__vault_session';
const REFRESH_COOKIE_NAME = '__vault_refresh';

/**
 * Get environment configuration
 */
function getConfig() {
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

/**
 * Get the session token from cookies
 */
async function getSessionToken(): Promise<string | null> {
  try {
    const cookieStore = cookies();
    const token = cookieStore.get(SESSION_COOKIE_NAME)?.value;
    return token || null;
  } catch {
    // Cookies not available (e.g., in some edge cases)
    return null;
  }
}

/**
 * Get the refresh token from cookies
 */
async function getRefreshToken(): Promise<string | null> {
  try {
    const cookieStore = cookies();
    const token = cookieStore.get(REFRESH_COOKIE_NAME)?.value;
    return token || null;
  } catch {
    return null;
  }
}

/**
 * Validate session token and return auth result
 * Cached per request to avoid redundant validation
 */
const validateSession = cache(async (): Promise<AuthResult> => {
  const token = await getSessionToken();

  if (!token) {
    return {
      userId: null,
      session: null,
      orgId: null,
      orgRole: null,
      isSignedIn: false,
    };
  }

  const { apiUrl, tenantId, secretKey } = getConfig();

  try {
    // Try JWT verification first (works in Edge runtime)
    let validationResult: TokenValidationResult;

    if (secretKey) {
      // Use JWT verification if we have a secret key
      validationResult = await verifyToken(token, secretKey);
    } else {
      // Fall back to API validation
      const authClient = createAuthClient(apiUrl, tenantId);
      validationResult = await authClient.validateSession(token);
    }

    if (!validationResult.valid) {
      return {
        userId: null,
        session: null,
        orgId: null,
        orgRole: null,
        isSignedIn: false,
      };
    }

    // Construct session object from claims
    const session = {
      id: validationResult.sessionId!,
      userId: validationResult.userId!,
      token,
      expiresAt: validationResult.expiresAt
        ? new Date(validationResult.expiresAt * 1000)
        : new Date(Date.now() + 24 * 60 * 60 * 1000),
    };

    return {
      userId: validationResult.userId!,
      session,
      orgId: validationResult.orgId || null,
      orgRole: validationResult.orgRole || null,
      isSignedIn: true,
    };
  } catch (error) {
    console.error('[Vault] Session validation error:', error);
    return {
      userId: null,
      session: null,
      orgId: null,
      orgRole: null,
      isSignedIn: false,
    };
  }
});

/**
 * Get authentication state for the current request
 * 
 * @returns AuthResult containing userId, session, orgId, and isSignedIn
 * 
 * @example
 * ```tsx
 * // app/dashboard/page.tsx
 * import { auth } from '@vault/nextjs/server';
 * import { redirect } from 'next/navigation';
 * 
 * export default async function Dashboard() {
 *   const { userId, isSignedIn } = await auth();
 *   
 *   if (!isSignedIn) {
 *     redirect('/sign-in');
 *   }
 *   
 *   return <div>Dashboard</div>;
 * }
 * ```
 */
export async function auth(): Promise<AuthResult> {
  return validateSession();
}

/**
 * Get the current authenticated user
 * 
 * @returns User object if authenticated, null otherwise
 * 
 * @example
 * ```tsx
 * // app/profile/page.tsx
 * import { currentUser } from '@vault/nextjs/server';
 * 
 * export default async function Profile() {
 *   const user = await currentUser();
 *   
 *   if (!user) {
 *     return <div>Not signed in</div>;
 *   }
 *   
 *   return <div>Hello, {user.name}</div>;
 * }
 * ```
 */
export async function currentUser(): Promise<User | null> {
  const { userId, isSignedIn } = await validateSession();

  if (!isSignedIn || !userId) {
    return null;
  }

  const { apiUrl, tenantId } = getConfig();
  const token = await getSessionToken();

  if (!token) {
    return null;
  }

  try {
    const response = await fetch(`${apiUrl}/v1/users/${userId}`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'X-Tenant-ID': tenantId,
        'Content-Type': 'application/json',
      },
      cache: 'no-store',
    });

    if (!response.ok) {
      if (response.status === 401) {
        return null;
      }
      throw new Error(`Failed to fetch user: ${response.statusText}`);
    }

    const data = await response.json();
    return data.user as User;
  } catch (error) {
    console.error('[Vault] Error fetching current user:', error);
    return null;
  }
}

/**
 * Get the session token for the current request
 * Useful for making authenticated API calls
 * 
 * @returns Session token string if authenticated, null otherwise
 * 
 * @example
 * ```tsx
 * // app/api/data/route.ts
 * import { getToken } from '@vault/nextjs/server';
 * 
 * export async function GET() {
 *   const token = await getToken();
 *   
 *   const data = await fetch('https://api.example.com/data', {
 *     headers: {
 *       'Authorization': `Bearer ${token}`,
 *     },
 *   });
 *   
 *   return Response.json(await data.json());
 * }
 * ```
 */
export async function getToken(): Promise<string | null> {
  const { isSignedIn } = await validateSession();

  if (!isSignedIn) {
    return null;
  }

  return getSessionToken();
}

/**
 * Protect a server component or action
 * Throws an error if the user is not authenticated
 * 
 * @throws Error if not authenticated
 * 
 * @example
 * ```tsx
 * // app/admin/page.tsx
 * import { protect } from '@vault/nextjs/server';
 * 
 * export default async function AdminPage() {
 *   const { userId } = await protect();
 *   
 *   return <div>Admin Dashboard</div>;
 * }
 * ```
 */
export async function protect(): Promise<AuthResult> {
  const authResult = await validateSession();

  if (!authResult.isSignedIn) {
    throw new Error('Unauthorized');
  }

  return authResult;
}

/**
 * Check if the current user has a specific organization role
 * 
 * @param roles - Array of allowed roles
 * @returns boolean indicating if the user has one of the roles
 * 
 * @example
 * ```tsx
 * // app/team/page.tsx
 * import { hasRole } from '@vault/nextjs/server';
 * import { redirect } from 'next/navigation';
 * 
 * export default async function TeamPage() {
 *   const hasAdminRole = await hasRole(['admin', 'owner']);
 *   
 *   if (!hasAdminRole) {
 *     redirect('/');
 *   }
 *   
 *   return <div>Team Management</div>;
 * }
 * ```
 */
export async function hasRole(roles: string[]): Promise<boolean> {
  const { orgRole } = await validateSession();

  if (!orgRole) {
    return false;
  }

  return roles.includes(orgRole);
}

/**
 * Sign out the current user (server action)
 * 
 * @example
 * ```tsx
 * // app/components/SignOutButton.tsx
 * import { signOut } from '@vault/nextjs/server';
 * 
 * export function SignOutButton() {
 *   return (
 *     <form action={signOut}>
 *       <button type="submit">Sign Out</button>
 *     </form>
 *   );
 * }
 * ```
 */
export async function signOut(): Promise<void> {
  'use server';

  const { apiUrl, tenantId } = getConfig();
  const token = await getSessionToken();

  // Call the sign out API
  if (token) {
    try {
      await fetch(`${apiUrl}/v1/auth/signout`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'X-Tenant-ID': tenantId,
          'Content-Type': 'application/json',
        },
      });
    } catch (error) {
      console.error('[Vault] Sign out error:', error);
    }
  }

  // Clear cookies
  try {
    const cookieStore = cookies();
    cookieStore.delete(SESSION_COOKIE_NAME);
    cookieStore.delete(REFRESH_COOKIE_NAME);
  } catch {
    // Cookies not available
  }
}
