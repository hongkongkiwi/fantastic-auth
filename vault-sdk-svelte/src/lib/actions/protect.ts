/**
 * protect Action
 * 
 * Svelte action to protect DOM elements based on authentication.
 * 
 * @example
 * ```svelte
 * <div use:protect>
 *   This content is only visible to authenticated users
 * </div>
 * 
 * <div use:protect={{ role: 'admin', fallback: () => console.log('Not authorized') }}>
 *   This content is only visible to admins
 * </div>
 * ```
 */

import type { Action } from 'svelte/action';
import type { OrganizationRole } from '../types.js';
import { getVaultContext } from '../context.js';

export interface ProtectActionOptions {
  /** Required role for access */
  role?: OrganizationRole;
  /** Required permission */
  permission?: string;
  /** Called when user is not authorized */
  onUnauthorized?: () => void;
  /** Whether to hide (display: none) or remove (remove from DOM) the element */
  mode?: 'hide' | 'remove';
  /** Content to show when unauthorized (as HTML string) */
  fallback?: string;
}

/**
 * Svelte action to protect DOM elements
 * 
 * Usage:
 * ```svelte
 * <div use:protect>
 *   Protected content
 * </div>
 * ```
 */
export const protect: Action<HTMLElement, ProtectActionOptions | undefined> = (
  node,
  options = {}
) => {
  const { 
    role, 
    permission, 
    onUnauthorized, 
    mode = 'hide',
    fallback 
  } = options;
  
  let vault: ReturnType<typeof getVaultContext>;
  
  try {
    vault = getVaultContext();
  } catch {
    // No vault context available
    console.warn('[Vault] protect action used outside of VaultProvider');
    return {
      destroy() {}
    };
  }
  
  // Store original content for restore
  const originalDisplay = node.style.display;
  const originalContent = node.innerHTML;
  
  function checkAuth() {
    let isSignedIn = false;
    let user = null;
    let organization = null;
    
    const unsubSignedIn = vault.isSignedIn.subscribe(v => isSignedIn = v);
    const unsubUser = vault.user.subscribe(v => user = v);
    const unsubOrg = vault.organization.subscribe(v => organization = v);
    
    unsubSignedIn();
    unsubUser();
    unsubOrg();
    
    // Check authentication
    if (!isSignedIn || !user) {
      return false;
    }
    
    // Check role
    if (role && organization?.role !== role) {
      const roleHierarchy: Record<OrganizationRole, number> = {
        owner: 4,
        admin: 3,
        member: 2,
        guest: 1
      };
      
      const userRoleLevel = roleHierarchy[organization?.role || 'guest'] || 0;
      const requiredRoleLevel = roleHierarchy[role] || 0;
      
      if (userRoleLevel < requiredRoleLevel) {
        return false;
      }
    }
    
    // Check permission
    if (permission) {
      // Permission checking logic here
      // This is a placeholder - expand based on your permission system
      return false;
    }
    
    return true;
  }
  
  function updateVisibility() {
    const isAuthorized = checkAuth();
    
    if (isAuthorized) {
      // Restore visibility
      node.style.display = originalDisplay;
      if (fallback) {
        node.innerHTML = originalContent;
      }
    } else {
      // Hide or remove
      if (mode === 'hide') {
        node.style.display = 'none';
      } else {
        node.innerHTML = '';
      }
      
      // Show fallback if provided
      if (fallback) {
        node.innerHTML = fallback;
        node.style.display = originalDisplay;
      }
      
      onUnauthorized?.();
    }
  }
  
  // Subscribe to auth state changes
  const unsubscribers: (() => void)[] = [];
  
  unsubscribers.push(vault.isSignedIn.subscribe(() => updateVisibility()));
  unsubscribers.push(vault.user.subscribe(() => updateVisibility()));
  unsubscribers.push(vault.organization.subscribe(() => updateVisibility()));
  
  // Initial check
  updateVisibility();
  
  return {
    destroy() {
      unsubscribers.forEach(unsub => unsub());
      // Restore original state
      node.style.display = originalDisplay;
      if (fallback) {
        node.innerHTML = originalContent;
      }
    },
    update(newOptions: ProtectActionOptions) {
      // Update options and re-check
      Object.assign(options, newOptions);
      updateVisibility();
    }
  };
};
