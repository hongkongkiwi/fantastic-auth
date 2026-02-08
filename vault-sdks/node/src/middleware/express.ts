/**
 * Express middleware for Vault Auth
 */

import { Request, Response, NextFunction, RequestHandler } from 'express';
import { VaultAuth } from '../client.js';
import { User, TokenPayload } from '../types.js';
import { VaultAuthError, AuthenticationError, AuthorizationError } from '../errors.js';

// Extend Express Request interface
declare global {
  namespace Express {
    interface Request {
      vaultUser?: User;
      vaultToken?: string;
      vaultTokenPayload?: TokenPayload;
    }
  }
}

/** Options for Express middleware */
export interface ExpressMiddlewareOptions {
  /** Vault Auth client */
  client: VaultAuth;
  /** Paths to exclude from authentication */
  excludedPaths?: string[];
}

/**
 * Create Express middleware for Vault authentication
 * @param options - Middleware options
 * @returns Express middleware handler
 */
export function vaultAuthMiddleware(options: ExpressMiddlewareOptions): RequestHandler {
  const { client, excludedPaths = [] } = options;

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      // Skip excluded paths
      if (excludedPaths.some((path) => req.path.startsWith(path))) {
        next();
        return;
      }

      // Extract token
      const authHeader = req.headers.authorization;
      if (!authHeader?.startsWith('Bearer ')) {
        next();
        return;
      }

      const token = authHeader.slice(7);

      // Verify token
      const user = await client.verifyToken(token);
      const payload = client.decodeToken(token);

      // Attach to request
      req.vaultUser = user;
      req.vaultToken = token;
      req.vaultTokenPayload = payload;

      next();
    } catch (error) {
      // Continue without setting user (will be handled by requireAuth if needed)
      next();
    }
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
 * @returns Express middleware handler
 */
export function requireAuth(options: RequireAuthOptions = {}): RequestHandler {
  const { roles, requireOrg = false, errorMessage = 'Authentication required' } = options;

  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.vaultUser) {
      res.status(401).json({ error: errorMessage });
      return;
    }

    if (requireOrg) {
      const payload = req.vaultTokenPayload;
      if (!payload?.orgId) {
        res.status(403).json({ error: 'Organization membership required' });
        return;
      }

      if (roles && roles.length > 0 && !roles.includes(payload.orgRole || '')) {
        res.status(403).json({ error: `Required role: ${roles.join(', ')}` });
        return;
      }
    }

    next();
  };
}

/**
 * Create middleware that requires organization membership
 * @param orgIdParam - Route parameter name for organization ID
 * @returns Express middleware handler
 */
export function requireOrgMember(orgIdParam: string = 'orgId'): RequestHandler {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.vaultUser) {
      res.status(401).json({ error: 'Authentication required' });
      return;
    }

    const orgId = req.params[orgIdParam];
    const payload = req.vaultTokenPayload;

    if (!payload?.orgId || payload.orgId !== orgId) {
      res.status(403).json({ error: 'Not a member of this organization' });
      return;
    }

    next();
  };
}

/**
 * Error handler for VaultAuthError
 * @param err - Error object
 * @param req - Express request
 * @param res - Express response
 * @param next - Next function
 */
export function vaultErrorHandler(
  err: Error,
  req: Request,
  res: Response,
  next: NextFunction
): void {
  if (err instanceof VaultAuthError) {
    const statusCode = err.statusCode || 500;
    res.status(statusCode).json({
      error: err.message,
      code: err.errorCode,
    });
    return;
  }
  next(err);
}

/**
 * Get current authenticated user from request
 * @param req - Express request
 * @returns Current user or undefined
 */
export function getCurrentUser(req: Request): User | undefined {
  return req.vaultUser;
}

/**
 * Get current token payload from request
 * @param req - Express request
 * @returns Token payload or undefined
 */
export function getCurrentTokenPayload(req: Request): TokenPayload | undefined {
  return req.vaultTokenPayload;
}

// Convenience re-exports
export { VaultAuth, User, TokenPayload };
