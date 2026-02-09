/**
 * @fantasticauth/nextjs - Next.js SDK for Vault
 * 
 * This is the main entry point for client-side usage.
 * For server-side utilities, use `@fantasticauth/nextjs/server`
 * For API route handlers, use `@fantasticauth/nextjs/api`
 * 
 * @example
 * ```tsx
 * // app/layout.tsx
 * import { VaultProvider } from '@fantasticauth/nextjs';
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
export {
  VaultProvider,
  FantasticauthProvider,
  useFantasticauthContext,
} from './client/VaultProvider';
export { useAuth, useUser, useSession } from './client/ClientComponents';

// Re-export types
export type {
  AuthResult,
  AuthMiddlewareOptions,
  VaultProviderConfig,
  VaultProviderConfig as FantasticauthProviderConfig,
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
export type {
  VaultProviderProps,
  FantasticauthProviderProps,
} from './client/VaultProvider';
