# Vault Auth Node.js SDK

Official Node.js/TypeScript SDK for Vault authentication and user management.

## Installation

```bash
npm install @fantasticauth/auth
```

## Quick Start

```typescript
import { VaultAuth } from '@fantasticauth/auth';

// Initialize client
const vault = new VaultAuth({
  apiKey: 'vault_m2m_your_key_here',
  baseURL: 'https://api.vault.dev'
});

// Verify a JWT token
const user = await vault.verifyToken('eyJhbGciOiJSUzI1NiIs...');
console.log(user.email);

// Get user by ID
const user = await vault.users.get('user_123');

// Create a new user
const newUser = await vault.users.create({
  email: 'new@example.com',
  password: 'secure_password',
  firstName: 'John',
  lastName: 'Doe'
});
```

## Configuration

```typescript
const vault = new VaultAuth({
  apiKey: 'vault_m2m_...',        // Required
  baseURL: 'https://api.vault.dev', // Default
  timeout: 30000,                  // Default (milliseconds)
  maxRetries: 3,                   // Default
  retryDelay: 1000,                // Default (milliseconds)
  requestId: 'trace-123',          // Optional
  jwksCacheTTL: 3600000,           // Default (milliseconds)
});
```

## User Management

```typescript
// List users
const usersPage = await vault.users.list({ page: 1, perPage: 20 });
for (const user of usersPage.data) {
  console.log(user.email);
}

// Get user by email
const user = await vault.users.getByEmail('user@example.com');

// Update user
const updated = await vault.users.update('user_123', {
  firstName: 'Jane',
  lastName: 'Smith'
});

// Delete user
await vault.users.delete('user_123');

// Get user's organizations
const memberships = await vault.users.getOrganizations('user_123');
for (const membership of memberships) {
  console.log(`${membership.organization?.name} - ${membership.role}`);
}

// Get user's sessions
const sessions = await vault.users.getSessions('user_123');
```

## Organization Management

```typescript
// Create organization
const org = await vault.organizations.create({
  name: 'Acme Corp',
  slug: 'acme-corp'
});

// Get organization
const org = await vault.organizations.get('org_123');

// Update organization
await vault.organizations.update('org_123', {
  name: 'Acme Corporation'
});

// Delete organization
await vault.organizations.delete('org_123');

// Manage members
await vault.organizations.addMember('org_123', {
  userId: 'user_123',
  role: 'admin'
});
await vault.organizations.updateMemberRole('org_123', 'user_123', {
  role: 'owner'
});
await vault.organizations.removeMember('org_123', 'user_123');

// Get members
const members = await vault.organizations.getMembers('org_123');
```

## Session Management

```typescript
// Get session
const session = await vault.sessions.get('session_123');

// Revoke session
await vault.sessions.revoke('session_123');

// Revoke all user sessions
await vault.sessions.revokeAllUserSessions('user_123');
```

## Express Integration

```typescript
import express from 'express';
import { VaultAuth, vaultAuthMiddleware, requireAuth } from '@fantasticauth/auth';
import { vaultErrorHandler } from '@fantasticauth/auth/middleware/express';

const app = express();

const vault = new VaultAuth({
  apiKey: 'vault_m2m_...',
  baseURL: 'https://api.vault.dev'
});

// Apply middleware
app.use(vaultAuthMiddleware({
  client: vault,
  excludedPaths: ['/health', '/public']
}));

// Protected route
app.get('/protected', (req, res) => {
  res.json({ email: req.vaultUser?.email });
});

// Route requiring authentication
app.get('/admin', requireAuth({ roles: ['admin', 'owner'] }), (req, res) => {
  res.json({ message: 'Admin area' });
});

// Error handler
app.use(vaultErrorHandler);

app.listen(3000);
```

## Fastify Integration

```typescript
import Fastify from 'fastify';
import vaultAuthPlugin, { requireAuth, requireOrgMember } from '@fantasticauth/auth/middleware/fastify';
import { VaultAuth } from '@fantasticauth/auth';

const fastify = Fastify({ logger: true });

const vault = new VaultAuth({
  apiKey: 'vault_m2m_...',
  baseURL: 'https://api.vault.dev'
});

// Register plugin
await fastify.register(vaultAuthPlugin, {
  client: vault,
  excludedPaths: ['/health']
});

// Protected route
fastify.get('/protected', async (request, reply) => {
  return { email: request.vaultUser?.email };
});

// Route requiring authentication
fastify.get('/admin', {
  preHandler: requireAuth({ roles: ['admin'] })
}, async (request, reply) => {
  return { message: 'Admin area' };
});

await fastify.listen({ port: 3000 });
```

## Koa Integration

```typescript
import Koa from 'koa';
import Router from '@koa/router';
import { VaultAuth, vaultAuthMiddleware, requireAuth } from '@fantasticauth/auth/middleware/koa';

const app = new Koa();
const router = new Router();

const vault = new VaultAuth({
  apiKey: 'vault_m2m_...',
  baseURL: 'https://api.vault.dev'
});

// Apply middleware
app.use(vaultAuthMiddleware({
  client: vault,
  excludedPaths: ['/health']
}));

// Protected route
router.get('/protected', (ctx) => {
  ctx.body = { email: ctx.vaultUser?.email };
});

// Route requiring authentication
router.get('/admin', requireAuth({ roles: ['admin'] }), (ctx) => {
  ctx.body = { message: 'Admin area' };
});

app.use(router.routes());
app.listen(3000);
```

## Error Handling

```typescript
import {
  VaultAuth,
  AuthenticationError,
  NotFoundError,
  RateLimitError,
  ServerError,
  isVaultAuthError
} from '@fantasticauth/auth';

const vault = new VaultAuth({ apiKey: 'vault_m2m_...' });

try {
  const user = await vault.users.get('user_123');
} catch (error) {
  if (error instanceof NotFoundError) {
    console.log(`User ${error.resourceId} not found`);
  } else if (error instanceof RateLimitError) {
    console.log(`Rate limited, retry after: ${error.retryAfter}s`);
  } else if (error instanceof ServerError) {
    console.log(`Server error: ${error.statusCode}`);
  } else if (isVaultAuthError(error)) {
    console.log(`Vault error: ${error.message}`);
  } else {
    console.log(`Unknown error: ${error}`);
  }
}
```

## Token Verification

```typescript
// Verify token and get user
const user = await vault.verifyToken('eyJhbGc...');

// Decode token without verification
const payload = vault.decodeToken('eyJhbGc...');
console.log(payload.sub);  // User ID
console.log(payload.orgId);  // Organization ID
console.log(payload.orgRole);  // Organization role

// Get JWKS for manual verification
const jwks = await vault.getJWKS();
for (const key of jwks.keys) {
  console.log(`Key ID: ${key.kid}, Algorithm: ${key.alg}`);
}
```

## Advanced Usage

### Custom HTTP Client Settings

```typescript
const vault = new VaultAuth({
  apiKey: 'vault_m2m_...',
  baseURL: 'https://api.vault.dev',
  timeout: 60000,
  maxRetries: 5,
  retryDelay: 2000,
  requestId: 'x-request-id-from-header',
});
```

### Request ID Tracing

```typescript
// Pass request ID for distributed tracing
const vault = new VaultAuth({
  apiKey: 'vault_m2m_...',
  requestId: request.headers['x-request-id'] as string
});
```

## TypeScript Support

Full TypeScript types are included. Import types as needed:

```typescript
import { User, Organization, TokenPayload, VaultAuthConfig } from '@fantasticauth/auth';

function processUser(user: User): string {
  return user.email;
}
```

## License

MIT License - see LICENSE file for details.
