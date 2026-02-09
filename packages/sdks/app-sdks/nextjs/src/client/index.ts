/**
 * @vault/nextjs/client - Client-side components for Vault
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
 * 
 * @example
 * ```tsx
 * // app/components/Profile.tsx
 * 'use client';
 * 
 * import { useUser, useAuth } from '@vault/nextjs/client';
 * 
 * export function Profile() {
 *   const { user, isLoaded } = useUser();
 *   const { signOut } = useAuth();
 *   
 *   if (!isLoaded) return <div>Loading...</div>;
 *   if (!user) return <div>Not signed in</div>;
 *   
 *   return (
 *     <div>
 *       <p>Hello, {user.name}</p>
 *       <button onClick={() => signOut()}>Sign Out</button>
 *     </div>
 *   );
 * }
 * ```
 */

export { VaultProvider } from './VaultProvider';
export { useAuth, useUser, useSession, useOrganization } from './ClientComponents';

// Re-export types
export type {
  AuthState,
  VaultProviderConfig,
  User,
  Session,
} from '../types';
