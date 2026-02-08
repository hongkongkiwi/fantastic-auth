/**
 * Koa middleware for Vault Auth
 */

import { Context, Next, Middleware } from 'koa';
import { VaultAuth } from '../client.js';
import { User, TokenPayload } from '../types.js';
import { VaultAuthError } from '../errors.js';

// Extend Koa Context interface
declare module 'koa' {
  interface Context {
    vaultUser?: User;
    vaultToken?: string;
    vaultTokenPayload?: TokenPayload;
  }
}

/** Options for Koa middleware */
export interface KoaMiddlewareOptions {
  /** Vault Auth client */
  client: VaultAuth;
  /** Paths to exclude from authentication */
  excludedPaths?: string[];
}

/**
 * Create Koa middleware for Vault authentication
 * @param options - Middleware options
 * @returns Koa middleware
 */
export function vaultAuthMiddleware(options: KoaMiddlewareOptions): Middleware {
  const { client, excludedPaths = [] } = options;

  return async (ctx: Context, next: Next): Promise<void> => {
    // Skip excluded paths
    if (excludedPaths.some((path) => ctx.path.startsWith(path))) {
      await next();
      return;
    }

    // Extract token
    const authHeader = ctx.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      await next();
      return;
    }

    const token = authHeader.slice(7);

    try {
      // Verify token
      const user = await client.verifyToken(token);
      const payload = client.decodeToken(token);

      // Attach to context
      ctx.vaultUser = user;
      ctx.vaultToken = token;
      ctx.vaultTokenPayload = payload;
    } catch (error) {
      // Continue without setting user
    }

    await next();
  };
}

/** Options for requireAuth middleware */
export interface RequireAuthOptions {
  /** Required organization roles */
  roles?: string[];
  /** Whether organization membership is required */
  requireOrg?: boolean;
  /** Custom error message */
  errorMessage?: string;
}

/**
 * Create middleware that requires authentication
 * @param options - Auth requirements
 * @returns Koa middleware
 */
export function requireAuth(options: RequireAuthOptions = {}): Middleware {
  const { roles, requireOrg = false, errorMessage = 'Authentication required' } = options;

  return async (ctx: Context, next: Next): Promise<void> => {
    if (!ctx.vaultUser) {
      ctx.status = 401;
      ctx.body = { error: errorMessage };
      return;
    }

    if (requireOrg) {
      const payload = ctx.vaultTokenPayload;
      if (!payload?.orgId) {
        ctx.status = 403;
        ctx.body = { error: 'Organization membership required' };
        return;
      }

      if (roles && roles.length > 0 && !roles.includes(payload.orgRole || '')) {
        ctx.status = 403;
        ctx.body = { error: `Required role: ${roles.join(', ')}` };
        return;
      }
    }

    await next();
  };
}

/**
 * Create middleware that requires organization membership
 * @param orgIdParam - Route parameter name for organization ID
 * @returns Koa middleware
 */
export function requireOrgMember(orgIdParam: string = 'orgId'): Middleware {
  return async (ctx: Context, next: Next): Promise<void> => {
    if (!ctx.vaultUser) {
      ctx.status = 401;
      ctx.body = { error: 'Authentication required' };
      return;
    }

    const orgId = ctx.params[orgIdParam];
    const payload = ctx.vaultTokenPayload;

    if (!payload?.orgId || payload.orgId !== orgId) {
      ctx.status = 403;
      ctx.body = { error: 'Not a member of this organization' };
      return;
    }

    await next();
  };
}

/**
 * Koa error handler middleware for VaultAuthError
 * @param ctx - Koa context
 * @param next - Next function
 */
export async function vaultErrorHandler(ctx: Context, next: Next): Promise<void> {
  try {
    await next();
  } catch (err) {
    if (err instanceof VaultAuthError) {
      const statusCode = err.statusCode || 500;
      ctx.status = statusCode;
      ctx.body = {
        error: err.message,
        code: err.errorCode,
      };
      return;
    }
    throw err;
  }
}

/**
 * Get current authenticated user from context
 * @param ctx - Koa context
 * @returns Current user or undefined
 */
export function getCurrentUser(ctx: Context): User | undefined {
  return ctx.vaultUser;
}

/**
 * Get current token payload from context
 * @param ctx - Koa context
 * @returns Token payload or undefined
 */
export function getCurrentTokenPayload(ctx: Context): TokenPayload | undefined {
  return ctx.vaultTokenPayload;
}

// Convenience re-exports
export { VaultAuth, User, TokenPayload };
