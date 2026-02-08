/**
 * Tests for framework middleware
 */

import { Request, Response } from 'express';
import { VaultAuth } from '../src/index.js';
import { vaultAuthMiddleware, requireAuth, requireOrgMember } from '../src/middleware/express.js';

describe('Express Middleware', () => {
  const mockVault = {
    verifyToken: jest.fn(),
    decodeToken: jest.fn(),
  } as unknown as VaultAuth;

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('vaultAuthMiddleware', () => {
    it('should set user on request when valid token provided', async () => {
      const middleware = vaultAuthMiddleware({ client: mockVault });
      const req = {
        headers: { authorization: 'Bearer valid_token' },
        path: '/protected'
      } as Request;
      const res = {} as Response;
      const next = jest.fn();

      const mockUser = {
        id: 'user_123',
        email: 'test@example.com',
        emailVerified: true,
        status: 'active' as const
      };

      (mockVault.verifyToken as jest.Mock).mockResolvedValue(mockUser);
      (mockVault.decodeToken as jest.Mock).mockReturnValue({ sub: 'user_123', orgId: 'org_123' });

      await middleware(req, res, next);

      expect(req.vaultUser).toEqual(mockUser);
      expect(req.vaultToken).toBe('valid_token');
      expect(next).toHaveBeenCalled();
    });

    it('should skip excluded paths', async () => {
      const middleware = vaultAuthMiddleware({
        client: mockVault,
        excludedPaths: ['/health']
      });
      const req = {
        headers: {},
        path: '/health'
      } as Request;
      const res = {} as Response;
      const next = jest.fn();

      await middleware(req, res, next);

      expect(mockVault.verifyToken).not.toHaveBeenCalled();
      expect(next).toHaveBeenCalled();
    });

    it('should continue without user when no authorization header', async () => {
      const middleware = vaultAuthMiddleware({ client: mockVault });
      const req = {
        headers: {},
        path: '/protected'
      } as Request;
      const res = {} as Response;
      const next = jest.fn();

      await middleware(req, res, next);

      expect(req.vaultUser).toBeUndefined();
      expect(next).toHaveBeenCalled();
    });
  });

  describe('requireAuth', () => {
    it('should call next when user is authenticated', () => {
      const middleware = requireAuth();
      const req = {
        vaultUser: { id: 'user_123', email: 'test@example.com' }
      } as Request;
      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn()
      } as unknown as Response;
      const next = jest.fn();

      middleware(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
    });

    it('should return 401 when user is not authenticated', () => {
      const middleware = requireAuth();
      const req = {} as Request;
      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn()
      } as unknown as Response;
      const next = jest.fn();

      middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({ error: 'Authentication required' });
      expect(next).not.toHaveBeenCalled();
    });

    it('should check organization role when required', () => {
      const middleware = requireAuth({ roles: ['admin'], requireOrg: true });
      const req = {
        vaultUser: { id: 'user_123', email: 'test@example.com' },
        vaultTokenPayload: { orgId: 'org_123', orgRole: 'member' }
      } as Request;
      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn()
      } as unknown as Response;
      const next = jest.fn();

      middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith({ error: 'Required role: admin' });
    });

    it('should pass when user has required role', () => {
      const middleware = requireAuth({ roles: ['admin'], requireOrg: true });
      const req = {
        vaultUser: { id: 'user_123', email: 'test@example.com' },
        vaultTokenPayload: { orgId: 'org_123', orgRole: 'admin' }
      } as Request;
      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn()
      } as unknown as Response;
      const next = jest.fn();

      middleware(req, res, next);

      expect(next).toHaveBeenCalled();
    });
  });

  describe('requireOrgMember', () => {
    it('should return 401 when user is not authenticated', () => {
      const middleware = requireOrgMember('orgId');
      const req = {
        params: { orgId: 'org_123' }
      } as unknown as Request;
      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn()
      } as unknown as Response;
      const next = jest.fn();

      middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
    });

    it('should return 403 when user is not member of organization', () => {
      const middleware = requireOrgMember('orgId');
      const req = {
        vaultUser: { id: 'user_123', email: 'test@example.com' },
        vaultTokenPayload: { orgId: 'org_456' },
        params: { orgId: 'org_123' }
      } as unknown as Request;
      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn()
      } as unknown as Response;
      const next = jest.fn();

      middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith({ error: 'Not a member of this organization' });
    });

    it('should pass when user is member of organization', () => {
      const middleware = requireOrgMember('orgId');
      const req = {
        vaultUser: { id: 'user_123', email: 'test@example.com' },
        vaultTokenPayload: { orgId: 'org_123' },
        params: { orgId: 'org_123' }
      } as unknown as Request;
      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn()
      } as unknown as Response;
      const next = jest.fn();

      middleware(req, res, next);

      expect(next).toHaveBeenCalled();
    });
  });
});
