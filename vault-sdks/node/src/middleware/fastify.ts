/**
 * Fastify plugin for Vault Auth
 */

import { FastifyInstance, FastifyRequest, FastifyReply, FastifyPluginAsync, FastifyError } from 'fastify';
import fp from 'fastify-plugin';
import { VaultAuth } from '../client.js';
import { User, TokenPayload } from '../types.js';
import { VaultAuthError } from '../errors.js';

// Extend Fastify interfaces
declare module 'fastify' {
  interface FastifyRequest {
    vaultUser?: User;
    vaultToken?: string;
    vaultTokenPayload?: TokenPayload;
  }

  interface FastifyInstance {
    vaultAuth: VaultAuth;
  }
}

/** Options for Fastify plugin */
export interface FastifyVaultAuthOptions {
  /** Vault Auth client */
  client: VaultAuth;
  /** Paths to exclude from authentication */
  excludedPaths?: string[];
}

/**
 * Fastify plugin for Vault authentication
 * @param fastify - Fastify instance
 * @param options - Plugin options
 */
const vaultAuthPlugin: FastifyPluginAsync<FastifyVaultAuthOptions> = async (
  fastify: FastifyInstance,
  options: FastifyVaultAuthOptions
): Promise<void> => {
  const { client, excludedPaths = [] } = options;

  // Store client in fastify instance
  fastify.decorate('vaultAuth', client);

  // Add hook to process authentication
  fastify.addHook('onRequest', async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    // Skip excluded paths
    if (excludedPaths.some((path) => request.url.startsWith(path))) {
      return;
    }

    // Extract token
    const authHeader = request.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      return;
    }

    const token = authHeader.slice(7);

    try {
      // Verify token
      const user = await client.verifyToken(token);
      const payload = client.decodeToken(token);

      // Attach to request
      request.vaultUser = user;
      request.vaultToken = token;
      request.vaultTokenPayload = payload;
    } catch (error) {
      // Continue without setting user
    }
  });

  // Add error handler
  fastify.setErrorHandler((error: FastifyError, request: FastifyRequest, reply: FastifyReply): void => {
    if (error instanceof VaultAuthError) {
      const statusCode = error.statusCode || 500;
      reply.status(statusCode).send({
        error: error.message,
        code: error.errorCode,
      });
      return;
    }
    // Re-throw for default handler
    throw error;
  });
};

export default fp(vaultAuthPlugin, { name: 'fastify-vault-auth' });

/** Options for requireAuth decorator */
export interface RequireAuthDecoratorOptions {
  /** Required organization roles */
  roles?: string[];
  /** Whether organization membership is required */
  requireOrg?: boolean;
}

/**
 * Require authentication preHandler decorator
 * @param options - Auth requirements
 * @returns Fastify preHandler
 */
export function requireAuth(options: RequireAuthDecoratorOptions = {}) {
  const { roles, requireOrg = false } = options;

  return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    if (!request.vaultUser) {
      reply.status(401).send({ error: 'Authentication required' });
      return;
    }

    if (requireOrg) {
      const payload = request.vaultTokenPayload;
      if (!payload?.orgId) {
        reply.status(403).send({ error: 'Organization membership required' });
        return;
      }

      if (roles && roles.length > 0 && !roles.includes(payload.orgRole || '')) {
        reply.status(403).send({ error: `Required role: ${roles.join(', ')}` });
        return;
      }
    }
  };
}

/**
 * Require organization membership preHandler decorator
 * @param orgIdParam - Route parameter name for organization ID
 * @returns Fastify preHandler
 */
export function requireOrgMember(orgIdParam: string = 'orgId') {
  return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    if (!request.vaultUser) {
      reply.status(401).send({ error: 'Authentication required' });
      return;
    }

    const orgId = (request.params as Record<string, string>)[orgIdParam];
    const payload = request.vaultTokenPayload;

    if (!payload?.orgId || payload.orgId !== orgId) {
      reply.status(403).send({ error: 'Not a member of this organization' });
      return;
    }
  };
}

// Convenience re-exports
export { VaultAuth, User, TokenPayload };
