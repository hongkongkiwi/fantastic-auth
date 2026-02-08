/**
 * API route handlers and utilities for Vault
 * 
 * Provides helpers for creating authenticated route handlers
 * and handling webhooks from Vault.
 */

import { cookies } from 'next/headers';
import type { NextRequest } from 'next/server';
import type { AuthResult, User, RouteHandlerOptions, ApiError } from '../types';
import { verifyToken, createAuthClient } from '../server/authClient';

// Cookie names
const SESSION_COOKIE_NAME = '__vault_session';
const REFRESH_COOKIE_NAME = '__vault_refresh';

/**
 * Get environment configuration
 */
function getConfig() {
  const apiUrl = process.env.VAULT_API_URL;
  const tenantId = process.env.VAULT_TENANT_ID;
  const secretKey = process.env.VAULT_SECRET_KEY;
  const webhookSecret = process.env.VAULT_WEBHOOK_SECRET;

  if (!apiUrl) {
    throw new Error('VAULT_API_URL environment variable is not set');
  }

  if (!tenantId) {
    throw new Error('VAULT_TENANT_ID environment variable is not set');
  }

  return { apiUrl, tenantId, secretKey, webhookSecret };
}

/**
 * Authenticated handler type
 */
export type AuthenticatedHandler = (
  request: Request | NextRequest,
  context: {
    auth: AuthResult;
    user: User | null;
    token: string | null;
  }
) => Promise<Response> | Response;

/**
 * Route handler configuration
 */
export interface RouteHandlerConfig {
  /**
   * Whether to require authentication
   * @default true
   */
  requireAuth?: boolean;
  /**
   * Allowed HTTP methods
   */
  methods?: string[];
  /**
   * Custom unauthorized response
   */
  onUnauthorized?: () => Response;
  /**
   * Required organization roles (if org context is needed)
   */
  requiredRoles?: string[];
}

/**
 * Get session token from request
 */
async function getTokenFromRequest(request: Request | NextRequest): Promise<string | null> {
  // Try cookie first
  try {
    const cookieStore = cookies();
    const cookieToken = cookieStore.get(SESSION_COOKIE_NAME)?.value;
    if (cookieToken) {
      return cookieToken;
    }
  } catch {
    // Cookies not available in edge runtime
  }

  // Try Authorization header
  const authHeader = request.headers.get('authorization');
  if (authHeader?.startsWith('Bearer ')) {
    return authHeader.slice(7);
  }

  return null;
}

/**
 * Validate authentication for a request
 */
async function validateAuth(
  request: Request | NextRequest
): Promise<{ auth: AuthResult; token: string | null }> {
  const token = await getTokenFromRequest(request);

  if (!token) {
    return {
      auth: {
        userId: null,
        session: null,
        orgId: null,
        orgRole: null,
        isSignedIn: false,
      },
      token: null,
    };
  }

  const { apiUrl, tenantId, secretKey } = getConfig();

  try {
    let validationResult;

    if (secretKey) {
      validationResult = await verifyToken(token, secretKey);
    } else {
      const authClient = createAuthClient(apiUrl, tenantId);
      validationResult = await authClient.validateSession(token);
    }

    if (!validationResult.valid) {
      return {
        auth: {
          userId: null,
          session: null,
          orgId: null,
          orgRole: null,
          isSignedIn: false,
        },
        token: null,
      };
    }

    const session = {
      id: validationResult.sessionId!,
      userId: validationResult.userId!,
      token,
      expiresAt: validationResult.expiresAt
        ? new Date(validationResult.expiresAt * 1000)
        : new Date(Date.now() + 24 * 60 * 60 * 1000),
    };

    return {
      auth: {
        userId: validationResult.userId!,
        session,
        orgId: validationResult.orgId || null,
        orgRole: validationResult.orgRole || null,
        isSignedIn: true,
      },
      token,
    };
  } catch {
    return {
      auth: {
        userId: null,
        session: null,
        orgId: null,
        orgRole: null,
        isSignedIn: false,
      },
      token: null,
    };
  }
}

/**
 * Fetch user data
 */
async function fetchUser(userId: string, token: string): Promise<User | null> {
  const { apiUrl, tenantId } = getConfig();

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
      return null;
    }

    const data = await response.json();
    return data.user as User;
  } catch {
    return null;
  }
}

/**
 * Default unauthorized response
 */
function defaultUnauthorizedResponse(): Response {
  return Response.json(
    {
      error: 'Unauthorized',
      code: 'authentication_required',
      message: 'Authentication is required to access this resource',
    } as ApiError,
    {
      status: 401,
      headers: {
        'WWW-Authenticate': 'Bearer',
      },
    }
  );
}

/**
 * Create default method not allowed response
 */
function methodNotAllowedResponse(allowed: string[]): Response {
  return Response.json(
    {
      error: 'Method Not Allowed',
      code: 'method_not_allowed',
      message: `Allowed methods: ${allowed.join(', ')}`,
    } as ApiError,
    {
      status: 405,
      headers: {
        Allow: allowed.join(', '),
      },
    }
  );
}

/**
 * Wrap a route handler with authentication
 * 
 * @param handler - The route handler function
 * @param options - Configuration options
 * @returns Wrapped handler
 * 
 * @example
 * ```tsx
 * // app/api/protected/route.ts
 * import { withAuth } from '@vault/nextjs/api';
 * 
 * export const GET = withAuth(async (request, { auth, user, token }) => {
 *   return Response.json({
 *     message: 'Hello, ' + user?.name,
 *     userId: auth.userId,
 *   });
 * });
 * ```
 */
export function withAuth(
  handler: AuthenticatedHandler,
  options: RouteHandlerConfig = {}
): (request: Request | NextRequest) => Promise<Response> {
  const { requireAuth = true, methods, onUnauthorized, requiredRoles } = options;

  return async function authenticatedHandler(request: Request | NextRequest): Promise<Response> {
    // Check method
    if (methods && methods.length > 0) {
      if (!methods.includes(request.method)) {
        return methodNotAllowedResponse(methods);
      }
    }

    // Validate authentication
    const { auth, token } = await validateAuth(request);

    // Check if auth is required
    if (requireAuth && !auth.isSignedIn) {
      return onUnauthorized ? onUnauthorized() : defaultUnauthorizedResponse();
    }

    // Check required roles
    if (requiredRoles && requiredRoles.length > 0) {
      if (!auth.orgRole || !requiredRoles.includes(auth.orgRole)) {
        return Response.json(
          {
            error: 'Forbidden',
            code: 'insufficient_permissions',
            message: 'You do not have permission to access this resource',
          } as ApiError,
          { status: 403 }
        );
      }
    }

    // Fetch user if authenticated
    const user = auth.isSignedIn && auth.userId && token
      ? await fetchUser(auth.userId, token)
      : null;

    // Call the handler
    return handler(request, { auth, user, token });
  };
}

/**
 * Create a route handler with multiple methods
 * 
 * @param handlers - Object mapping HTTP methods to handlers
 * @param options - Configuration options
 * @returns Route handler
 * 
 * @example
 * ```tsx
 * // app/api/resource/route.ts
 * import { createRouteHandler } from '@vault/nextjs/api';
 * 
 * export const { GET, POST, DELETE } = createRouteHandler({
 *   GET: async (request, { auth }) => {
 *     return Response.json({ items: [] });
 *   },
 *   POST: async (request, { auth }) => {
 *     const body = await request.json();
 *     return Response.json({ created: true });
 *   },
 *   DELETE: async (request, { auth }) => {
 *     return Response.json({ deleted: true });
 *   },
 * }, { requireAuth: true });
 * ```
 */
export function createRouteHandler(
  handlers: Record<string, AuthenticatedHandler>,
  options: RouteHandlerConfig = {}
): Record<string, (request: Request | NextRequest) => Promise<Response>> {
  const result: Record<string, (request: Request | NextRequest) => Promise<Response>> = {};

  for (const [method, handler] of Object.entries(handlers)) {
    result[method] = withAuth(handler, {
      ...options,
      methods: [method],
    });
  }

  return result;
}

// Webhook types
export interface WebhookEvent {
  type: string;
  data: Record<string, unknown>;
  timestamp: string;
  id: string;
}

export interface WebhookPayload {
  event: WebhookEvent;
  signature: string;
}

/**
 * Verify webhook signature
 * 
 * @param payload - The webhook payload
 * @param signature - The signature from headers
 * @param secret - The webhook secret
 * @returns Whether the signature is valid
 * 
 * @example
 * ```tsx
 * // app/api/webhooks/vault/route.ts
 * import { verifyWebhook } from '@vault/nextjs/api';
 * 
 * export async function POST(request: Request) {
 *   const payload = await request.json();
 *   const signature = request.headers.get('x-vault-signature');
 *   
 *   if (!verifyWebhook(payload, signature, process.env.VAULT_WEBHOOK_SECRET)) {
 *     return Response.json({ error: 'Invalid signature' }, { status: 400 });
 *   }
 *   
 *   // Handle webhook
 *   return Response.json({ received: true });
 * }
 * ```
 */
export function verifyWebhook(
  payload: Record<string, unknown>,
  signature: string | null,
  secret: string | undefined
): boolean {
  if (!signature || !secret) {
    return false;
  }

  // Simple HMAC verification (implement based on Vault's webhook format)
  // This is a placeholder - adjust based on actual webhook signature format
  try {
    // Import crypto for Node.js
    const crypto = require('crypto');
    const hmac = crypto.createHmac('sha256', secret);
    hmac.update(JSON.stringify(payload));
    const expectedSignature = hmac.digest('hex');
    
    return signature === expectedSignature;
  } catch {
    return false;
  }
}

/**
 * Handle incoming webhooks from Vault
 * 
 * @param request - The incoming request
 * @param handlers - Object mapping event types to handlers
 * @returns Response
 * 
 * @example
 * ```tsx
 * // app/api/webhooks/vault/route.ts
 * import { handleWebhook } from '@vault/nextjs/api';
 * 
 * export async function POST(request: Request) {
 *   return handleWebhook(request, {
 *     'user.created': async (event) => {
 *       // Handle user created event
 *       console.log('User created:', event.data.userId);
 *       return Response.json({ processed: true });
 *     },
 *     'user.updated': async (event) => {
 *       // Handle user updated event
 *       return Response.json({ processed: true });
 *     },
 *   });
 * }
 * ```
 */
export async function handleWebhook(
  request: Request,
  handlers: Record<string, (event: WebhookEvent) => Promise<Response>>
): Promise<Response> {
  const { webhookSecret } = getConfig();

  // Get signature from headers
  const signature = request.headers.get('x-vault-signature');

  // Parse payload
  let payload: Record<string, unknown>;
  try {
    payload = await request.json();
  } catch {
    return Response.json(
      { error: 'Invalid JSON payload' },
      { status: 400 }
    );
  }

  // Verify signature
  if (!verifyWebhook(payload, signature, webhookSecret)) {
    return Response.json(
      { error: 'Invalid signature' },
      { status: 400 }
    );
  }

  // Extract event
  const event = payload.event as WebhookEvent | undefined;
  if (!event || !event.type) {
    return Response.json(
      { error: 'Missing event data' },
      { status: 400 }
    );
  }

  // Find and call handler
  const handler = handlers[event.type];
  if (!handler) {
    // Return 200 for unhandled events (don't retry)
    return Response.json({ received: true, handled: false });
  }

  try {
    return await handler(event);
  } catch (error) {
    console.error('[Vault] Webhook handler error:', error);
    return Response.json(
      { error: 'Handler error' },
      { status: 500 }
    );
  }
}
