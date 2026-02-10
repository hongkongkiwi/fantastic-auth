import { createServer } from 'node:http';
import { describe, expect, it } from 'vitest';
import { TenantClient } from '../src/client';

describe('TenantClient integration with mocked server', () => {
  it('calls expected route and parses response', async () => {
    const requests: string[] = [];

    const server = createServer((req, res) => {
      if (!req.url) {
        res.statusCode = 500;
        res.end();
        return;
      }

      requests.push(`${req.method} ${req.url}`);

      if (req.url.startsWith('/api/v1/admin/users')) {
        res.statusCode = 200;
        res.setHeader('content-type', 'application/json');
        res.end(
          JSON.stringify({
            users: [{ id: 'user_1', email: 'user@example.com', status: 'active' }],
            total: 1,
            page: 1,
            per_page: 1,
          })
        );
        return;
      }

      if (req.url === '/api/v1/admin/system/health') {
        res.statusCode = 200;
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify({ status: 'healthy', version: '1.0.0', database: 'healthy' }));
        return;
      }

      res.statusCode = 404;
      res.end();
    });

    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));

    try {
      const address = server.address();
      if (!address || typeof address === 'string') {
        throw new Error('Failed to resolve test server address');
      }

      const client = new TenantClient({
        baseUrl: `http://127.0.0.1:${address.port}/api/v1`,
        token: 'token',
        tenantId: 'tenant_123',
      });

      const users = await client.listUsers({ perPage: 1, email: 'user@' });
      const health = await client.getSystemHealth();

      expect(users.users[0]?.id).toBe('user_1');
      expect(health.database).toBe('healthy');
      expect(requests).toContain('GET /api/v1/admin/users?per_page=1&email=user%40');
      expect(requests).toContain('GET /api/v1/admin/system/health');
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => {
          if (error) {
            reject(error);
            return;
          }
          resolve();
        });
      });
    }
  });
});
