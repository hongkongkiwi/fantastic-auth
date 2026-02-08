/**
 * Vue Router Navigation Guards
 *
 * Navigation guards for protecting routes with Vault authentication.
 *
 * @example
 * ```ts
 * // router/index.ts
 * import { createRouter, createWebHistory } from 'vue-router';
 * import { requireAuth, requireRole } from '@vault/vue/router';
 *
 * const router = createRouter({
 *   history: createWebHistory(),
 *   routes: [
 *     {
 *       path: '/dashboard',
 *       component: Dashboard,
 *       beforeEnter: requireAuth,
 *     },
 *     {
 *       path: '/admin',
 *       component: AdminPanel,
 *       beforeEnter: requireRole('admin'),
 *     },
 *   ],
 * });
 * ```
 */

import type { NavigationGuard, RouteLocationNormalized } from 'vue-router';
import type { VaultContextValue, OrganizationRole } from '../types';

/**
 * Get the Vault context from the global properties
 * This is a helper to access the vault instance in router guards
 */
function getVault(): VaultContextValue | undefined {
  // In a real implementation, you would store the vault instance
  // in a way that it's accessible from router guards
  // For now, we assume it's available on the window or via a global store
  return (window as any).__VAULT__;
}

/**
 * Navigation guard that requires authentication.
 * Redirects to sign-in page if user is not authenticated.
 *
 * @example
 * ```ts
 * {
 *   path: '/dashboard',
 *   component: Dashboard,
 *   beforeEnter: requireAuth,
 * }
 * ```
 */
export const requireAuth: NavigationGuard = async (
  to: RouteLocationNormalized,
  from: RouteLocationNormalized
) => {
  const vault = getVault();

  // If vault is not initialized, allow navigation
  // (the component should handle the loading state)
  if (!vault) {
    return true;
  }

  // Wait for auth to be loaded
  if (!vault.isLoaded.value) {
    // Wait a bit for auth to load
    await new Promise((resolve) => setTimeout(resolve, 100));
  }

  if (!vault.isSignedIn.value) {
    // Redirect to sign-in with return URL
    return {
      path: '/sign-in',
      query: { redirect: to.fullPath },
    };
  }

  return true;
};

/**
 * Navigation guard that requires a specific role.
 * Redirects to sign-in or shows unauthorized page if user doesn't have the role.
 *
 * @param role - The required role
 * @returns Navigation guard function
 *
 * @example
 * ```ts
 * {
 *   path: '/admin',
 *   component: AdminPanel,
 *   beforeEnter: requireRole('admin'),
 * }
 * ```
 */
export function requireRole(role: OrganizationRole): NavigationGuard {
  return async (to: RouteLocationNormalized, from: RouteLocationNormalized) => {
    const vault = getVault();

    if (!vault) {
      return true;
    }

    // Wait for auth to be loaded
    if (!vault.isLoaded.value) {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }

    if (!vault.isSignedIn.value) {
      return {
        path: '/sign-in',
        query: { redirect: to.fullPath },
      };
    }

    const userRole = vault.organization.value?.role;

    // Owner can access everything
    if (userRole === 'owner') {
      return true;
    }

    // Check if user has the required role
    if (userRole !== role) {
      // Redirect to unauthorized page or home
      return {
        path: '/unauthorized',
        query: { required: role },
      };
    }

    return true;
  };
}

/**
 * Navigation guard that requires any of the specified roles.
 *
 * @param roles - Array of allowed roles
 * @returns Navigation guard function
 *
 * @example
 * ```ts
 * {
 *   path: '/management',
 *   component: ManagementPanel,
 *   beforeEnter: requireAnyRole(['admin', 'owner']),
 * }
 * ```
 */
export function requireAnyRole(roles: OrganizationRole[]): NavigationGuard {
  return async (to: RouteLocationNormalized, from: RouteLocationNormalized) => {
    const vault = getVault();

    if (!vault) {
      return true;
    }

    if (!vault.isLoaded.value) {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }

    if (!vault.isSignedIn.value) {
      return {
        path: '/sign-in',
        query: { redirect: to.fullPath },
      };
    }

    const userRole = vault.organization.value?.role;

    // Owner can access everything
    if (userRole === 'owner') {
      return true;
    }

    if (!roles.includes(userRole as OrganizationRole)) {
      return {
        path: '/unauthorized',
      };
    }

    return true;
  };
}

/**
 * Navigation guard that requires a specific permission.
 *
 * @param permission - The required permission
 * @returns Navigation guard function
 *
 * @example
 * ```ts
 * {
 *   path: '/billing',
 *   component: BillingPage,
 *   beforeEnter: requirePermission('billing:write'),
 * }
 * ```
 */
export function requirePermission(permission: string): NavigationGuard {
  return async (to: RouteLocationNormalized, from: RouteLocationNormalized) => {
    const vault = getVault();

    if (!vault) {
      return true;
    }

    if (!vault.isLoaded.value) {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }

    if (!vault.isSignedIn.value) {
      return {
        path: '/sign-in',
        query: { redirect: to.fullPath },
      };
    }

    // Implement permission check logic here
    // This would typically check against user's permissions
    const userRole = vault.organization.value?.role;

    // Owner has all permissions
    if (userRole === 'owner') {
      return true;
    }

    // Admin has most permissions
    if (userRole === 'admin' && permission !== 'billing:write' && permission !== 'org:delete') {
      return true;
    }

    // Implement more granular permission checks as needed

    return {
      path: '/unauthorized',
    };
  };
}

/**
 * Navigation guard for guest-only routes (e.g., sign-in page).
 * Redirects authenticated users to a default route.
 *
 * @param redirectTo - Route to redirect authenticated users to (default: '/')
 * @returns Navigation guard function
 *
 * @example
 * ```ts
 * {
 *   path: '/sign-in',
 *   component: SignIn,
 *   beforeEnter: requireGuest('/dashboard'),
 * }
 * ```
 */
export function requireGuest(redirectTo: string = '/'): NavigationGuard {
  return async (to: RouteLocationNormalized, from: RouteLocationNormalized) => {
    const vault = getVault();

    if (!vault) {
      return true;
    }

    if (!vault.isLoaded.value) {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }

    if (vault.isSignedIn.value) {
      return redirectTo;
    }

    return true;
  };
}

/**
 * Meta-based navigation guard that checks route meta fields.
 * Use this as a global beforeEach guard.
 *
 * Route meta fields:
 * - requiresAuth: boolean - Requires user to be signed in
 * - requiresRole: string - Requires specific role
 * - requiresPermission: string - Requires specific permission
 * - guestOnly: boolean - Only for non-authenticated users
 *
 * @example
 * ```ts
 * // router/index.ts
 * import { createRouter } from 'vue-router';
 * import { createAuthGuard } from '@vault/vue/router';
 *
 * const router = createRouter({ ... });
 * router.beforeEach(createAuthGuard());
 * ```
 */
export function createAuthGuard(): NavigationGuard {
  return async (to: RouteLocationNormalized, from: RouteLocationNormalized) => {
    const vault = getVault();

    if (!vault) {
      return true;
    }

    const meta = to.meta;

    // Wait for auth to be loaded
    if (!vault.isLoaded.value) {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }

    // Check guest-only routes
    if (meta.guestOnly && vault.isSignedIn.value) {
      return meta.redirectAuthenticated || '/';
    }

    // Check auth requirement
    if (meta.requiresAuth && !vault.isSignedIn.value) {
      return {
        path: '/sign-in',
        query: { redirect: to.fullPath },
      };
    }

    // Check role requirement
    if (meta.requiresRole && vault.isSignedIn.value) {
      const userRole = vault.organization.value?.role;

      if (userRole !== 'owner' && userRole !== meta.requiresRole) {
        return {
          path: '/unauthorized',
        };
      }
    }

    // Check permission requirement
    if (meta.requiresPermission && vault.isSignedIn.value) {
      const userRole = vault.organization.value?.role;

      // Owner has all permissions
      if (userRole !== 'owner') {
        // Implement permission check
        // For now, just check admin can access non-billing settings
        if (userRole === 'admin' && meta.requiresPermission === 'billing:write') {
          return {
            path: '/unauthorized',
          };
        }
      }
    }

    return true;
  };
}
