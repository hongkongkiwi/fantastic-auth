/**
 * Tests for VaultAuth client
 */

import nock from 'nock';
import { VaultAuth, ConfigurationError, NotFoundError, RateLimitError, ServerError } from '../src/index.js';

const BASE_URL = 'https://api.vault.dev';
const API_KEY = 'vault_m2m_test_key_12345';

describe('VaultAuth', () => {
  afterEach(() => {
    nock.cleanAll();
  });

  describe('constructor', () => {
    it('should create client with valid config', () => {
      const client = new VaultAuth({ apiKey: API_KEY });
      expect(client).toBeDefined();
    });

    it('should throw ConfigurationError for missing API key', () => {
      expect(() => new VaultAuth({ apiKey: '' })).toThrow(ConfigurationError);
    });

    it('should throw ConfigurationError for invalid API key format', () => {
      expect(() => new VaultAuth({ apiKey: 'invalid_key' })).toThrow(ConfigurationError);
    });
  });

  describe('verifyToken', () => {
    it('should verify token successfully', async () => {
      // Mock JWKS endpoint
      nock(BASE_URL)
        .get('/.well-known/jwks.json')
        .reply(200, {
          keys: [{ kty: 'RSA', kid: 'key1', alg: 'RS256' }]
        });

      // Mock verify endpoint
      nock(BASE_URL)
        .post('/api/v1/auth/verify')
        .reply(200, {
          data: {
            id: 'user_123',
            email: 'test@example.com',
            emailVerified: true,
            status: 'active',
            firstName: 'Test',
            lastName: 'User'
          }
        });

      const client = new VaultAuth({ apiKey: API_KEY, baseURL: BASE_URL });
      
      // Create a dummy JWT with future expiration
      const header = Buffer.from(JSON.stringify({ alg: 'RS256', kid: 'key1' })).toString('base64url');
      const payload = Buffer.from(JSON.stringify({ sub: 'user_123', exp: 9999999999 })).toString('base64url');
      const token = `${header}.${payload}.signature`;

      const user = await client.verifyToken(token);

      expect(user.id).toBe('user_123');
      expect(user.email).toBe('test@example.com');
      expect(user.fullName).toBe('Test User');
    });
  });

  describe('users', () => {
    it('should get user by ID', async () => {
      nock(BASE_URL)
        .get('/api/v1/users/user_123')
        .reply(200, {
          data: {
            id: 'user_123',
            email: 'test@example.com',
            status: 'active'
          }
        });

      const client = new VaultAuth({ apiKey: API_KEY, baseURL: BASE_URL });
      const user = await client.users.get('user_123');

      expect(user.id).toBe('user_123');
      expect(user.email).toBe('test@example.com');
    });

    it('should throw NotFoundError for non-existent user', async () => {
      nock(BASE_URL)
        .get('/api/v1/users/notfound')
        .reply(404, {
          message: 'User not found',
          code: 'not_found'
        });

      const client = new VaultAuth({ apiKey: API_KEY, baseURL: BASE_URL });
      
      await expect(client.users.get('notfound')).rejects.toThrow(NotFoundError);
    });

    it('should create user', async () => {
      nock(BASE_URL)
        .post('/api/v1/users')
        .reply(201, {
          data: {
            id: 'user_new',
            email: 'new@example.com',
            status: 'pending_verification'
          }
        });

      const client = new VaultAuth({ apiKey: API_KEY, baseURL: BASE_URL });
      const user = await client.users.create({
        email: 'new@example.com',
        password: 'secure_password'
      });

      expect(user.id).toBe('user_new');
      expect(user.email).toBe('new@example.com');
    });

    it('should list users', async () => {
      nock(BASE_URL)
        .get('/api/v1/users')
        .query({ page: '1', per_page: '20' })
        .reply(200, {
          data: {
            users: [
              { id: 'user_1', email: 'user1@example.com', status: 'active' },
              { id: 'user_2', email: 'user2@example.com', status: 'active' }
            ],
            total: 2,
            page: 1,
            per_page: 20,
            has_more: false
          }
        });

      const client = new VaultAuth({ apiKey: API_KEY, baseURL: BASE_URL });
      const result = await client.users.list();

      expect(result.data).toHaveLength(2);
      expect(result.total).toBe(2);
    });

    it('should update user', async () => {
      nock(BASE_URL)
        .patch('/api/v1/users/user_123')
        .reply(200, {
          data: {
            id: 'user_123',
            email: 'test@example.com',
            firstName: 'Updated',
            lastName: 'Name'
          }
        });

      const client = new VaultAuth({ apiKey: API_KEY, baseURL: BASE_URL });
      const user = await client.users.update('user_123', { firstName: 'Updated', lastName: 'Name' });

      expect(user.firstName).toBe('Updated');
      expect(user.lastName).toBe('Name');
    });

    it('should delete user', async () => {
      nock(BASE_URL)
        .delete('/api/v1/users/user_123')
        .reply(204);

      const client = new VaultAuth({ apiKey: API_KEY, baseURL: BASE_URL });
      await expect(client.users.delete('user_123')).resolves.not.toThrow();
    });
  });

  describe('organizations', () => {
    it('should get organization by ID', async () => {
      nock(BASE_URL)
        .get('/api/v1/organizations/org_123')
        .reply(200, {
          data: {
            id: 'org_123',
            name: 'Test Org',
            slug: 'test-org',
            status: 'active'
          }
        });

      const client = new VaultAuth({ apiKey: API_KEY, baseURL: BASE_URL });
      const org = await client.organizations.get('org_123');

      expect(org.id).toBe('org_123');
      expect(org.name).toBe('Test Org');
    });

    it('should create organization', async () => {
      nock(BASE_URL)
        .post('/api/v1/organizations')
        .reply(201, {
          data: {
            id: 'org_new',
            name: 'New Org',
            slug: 'new-org',
            status: 'active'
          }
        });

      const client = new VaultAuth({ apiKey: API_KEY, baseURL: BASE_URL });
      const org = await client.organizations.create({ name: 'New Org', slug: 'new-org' });

      expect(org.id).toBe('org_new');
      expect(org.name).toBe('New Org');
    });
  });

  describe('retry logic', () => {
    it('should retry on server error', async () => {
      let attempts = 0;
      nock(BASE_URL)
        .get('/api/v1/users/user_123')
        .times(2)
        .reply(() => {
          attempts++;
          if (attempts < 2) {
            return [500, { message: 'Internal server error' }];
          }
          return [200, {
            data: {
              id: 'user_123',
              email: 'test@example.com',
              status: 'active'
            }
          }];
        });

      const client = new VaultAuth({ 
        apiKey: API_KEY, 
        baseURL: BASE_URL,
        maxRetries: 3,
        retryDelay: 10
      });
      
      const user = await client.users.get('user_123');

      expect(user.id).toBe('user_123');
      expect(attempts).toBe(2);
    });
  });

  describe('decodeToken', () => {
    it('should decode token payload', () => {
      const client = new VaultAuth({ apiKey: API_KEY });
      
      const payload = {
        sub: 'user_123',
        exp: 9999999999,
        iat: 1234567890,
        iss: 'vault',
        aud: 'api',
        jti: 'token_123'
      };
      
      const header = Buffer.from(JSON.stringify({ alg: 'RS256' })).toString('base64url');
      const payloadBase64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
      const token = `${header}.${payloadBase64}.signature`;

      const decoded = client.decodeToken(token);

      expect(decoded.sub).toBe('user_123');
      expect(decoded.exp).toBe(9999999999);
    });
  });
});
