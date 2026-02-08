/**
 * @vault/nextjs - Next.js SDK for Vault
 * 
 * This is the main entry point for client-side usage.
 * For server-side utilities, use `@vault/nextjs/server`
 * For API route handlers, use `@vault/nextjs/api`
 * 
 * @example
 * ```tsx
 * // app/layout.tsx
 * import { VaultProvider } from '@vault/nextjs';
 * 
 * export default function RootLayout({ children }) {
 *   return (
 *     <VaultProvider 
 *       apiUrl={process.env.NEXT_PUBLIC_VAULT_API_URL}
 *       tenantId={process.env.NEXT_PUBLIC_VAULT_TENANT_ID}
 *     >
 *       {children}
 *     </VaultProvider>
 *   );
 * }
 * ```
 */

// Re-export client components
export { VaultProvider } from './client/VaultProvider';
export { useAuth, useUser, useSession } from './client/ClientComponents';

// Re-export types
export type {
  AuthResult,
  AuthMiddlewareOptions,
  VaultProviderConfig,
  TokenValidationResult,
  CookieConfig,
  ServerAuthContext,
  RouteHandlerContext,
  RouteHandlerOptions,
  VaultJwtClaims,
  ApiError,
  AuthState,
  User,
  Session,
} from './types';
