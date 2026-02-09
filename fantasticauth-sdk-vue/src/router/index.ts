/**
 * Vault Vue SDK Router
 *
 * Vue Router integration for Vault authentication.
 */

export {
  requireAuth,
  requireRole,
  requireAnyRole,
  requirePermission,
  requireGuest,
  createAuthGuard,
} from './guards';
