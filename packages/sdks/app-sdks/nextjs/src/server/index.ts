/**
 * @vault/nextjs/server - Server-side utilities for Vault
 * 
 * @example
 * ```tsx
 * // app/dashboard/page.tsx
 * import { auth, currentUser } from '@vault/nextjs/server';
 * 
 * export default async function Dashboard() {
 *   const { userId, session } = await auth();
 *   const user = await currentUser();
 *   
 *   if (!userId) {
 *     redirect('/sign-in');
 *   }
 *   
 *   return <div>Hello {user?.name}</div>;
 * }
 * ```
 * 
 * @example
 * ```tsx
 * // middleware.ts
 * import { authMiddleware } from '@vault/nextjs/server';
 * 
 * export default authMiddleware({
 *   publicRoutes: ['/sign-in', '/sign-up', '/'],
 * });
 * ```
 */

export { auth, currentUser, getToken } from './auth';
export { authMiddleware } from './authMiddleware';
export { verifyToken, createAuthClient } from './authClient';

// Re-export types
export type {
  AuthResult,
  AuthMiddlewareOptions,
  TokenValidationResult,
  CookieConfig,
  ServerAuthContext,
  VaultJwtClaims,
} from '../types';
