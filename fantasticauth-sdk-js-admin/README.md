# Vault Admin API SDK

TypeScript SDK for the Vault Admin API. Designed for building admin dashboards and tenant management tools.

## Installation

```bash
npm install @vault/admin-sdk
# or
yarn add @vault/admin-sdk
# or
pnpm add @vault/admin-sdk
```

## Quick Start

```typescript
import { VaultAdminClient, UserManager } from '@vault/admin-sdk';

const client = new VaultAdminClient({
  baseUrl: 'https://api.vault.dev/api/v1',
  token: adminJwtToken,  // From your auth system
  tenantId: 'my-tenant'
});

// Get dashboard stats
const dashboard = await client.getDashboard();
console.log(`Total users: ${dashboard.totalUsers}`);

// Manage users
const users = new UserManager(client);
const allUsers = await users.getAll();
const stats = await users.getStats();
```

## Authentication

The Admin SDK requires a JWT token with admin role claims:

```typescript
const client = new VaultAdminClient({
  baseUrl: 'https://api.vault.dev/api/v1',
  token: 'eyJhbGciOiJSUzI1NiIs...', // Admin JWT
  tenantId: 'tenant-id',
  timeout: 30000 // optional
});
```

## Usage Guide

### Dashboard & Analytics

```typescript
// Get dashboard overview
const dashboard = await client.getDashboard();
console.log(`Active users: ${dashboard.activeUsers}`);
console.log(`New today: ${dashboard.newUsersToday}`);

// Get detailed metrics
const metrics = await client.getMetrics({
  from: '2024-01-01',
  to: '2024-01-31'
});

// Check system health
const health = await client.getSystemHealth();
console.log(`Database: ${health.services.database.status}`);
```

### User Management

```typescript
import { UserManager } from '@vault/admin-sdk';

const users = new UserManager(client);

// List all users
const allUsers = await users.getAll();

// Filter by status
const suspended = await users.getByStatus('suspended');

// Find by email
const user = await users.findByEmail('user@example.com');

// Create user
const newUser = await users.create({
  email: 'new@example.com',
  name: 'New User',
  password: 'secure-password',
  emailVerified: true
});

// Suspend user
await users.suspend(user.id, 'Policy violation');

// Force logout
await users.forceLogout(user.id);

// Get statistics
const stats = await users.getStats();
console.log(`MFA enabled: ${stats.mfaEnabled} users`);

// Find inactive users
const inactive = await users.getInactive(30); // 30+ days
```

### Organization Management

```typescript
import { OrganizationManager } from '@vault/admin-sdk';

const orgs = new OrganizationManager(client);

// Get all organizations
const organizations = await orgs.getAll();

// Get detailed info
const { organization, members } = await orgs.getDetails('org-123');

// Update member role
await orgs.updateMemberRole('org-123', 'user-456', 'admin');

// Remove member
await orgs.removeMember('org-123', 'user-789');

// Get statistics
const stats = await orgs.getStats();
console.log(`Average members per org: ${stats.averageMembersPerOrg}`);

// Find orphaned orgs (no members)
const orphaned = await orgs.getOrphaned();
```

### Audit Logs

```typescript
import { AuditManager } from '@vault/admin-sdk';

const audit = new AuditManager(client);

// Query recent activity
const recent = await audit.getRecent(100);

// Filter by user
const userActivity = await audit.getUserActivity('user-123', 7); // last 7 days

// Summarize actions
const summary = await audit.summarizeActions(30);
for (const action of summary) {
  console.log(`${action.action}: ${action.count} (${action.successCount} success)`);
}

// Detect suspicious activity
const suspicious = await audit.detectSuspiciousActivity(5, 1); // 5+ failures in 1 hour
for (const user of suspicious) {
  console.warn(`User ${user.userId} has ${user.actionCount} failed attempts`);
}

// Export for compliance
const export = await audit.exportForCompliance(
  new Date('2024-01-01'),
  new Date('2024-01-31')
);
```

### Tenant Settings

```typescript
import { SettingsManager } from '@vault/admin-sdk';

const settings = new SettingsManager(client);

// Get current settings
const current = await settings.get();

// Update password policy
await settings.updatePasswordPolicy({
  minLength: 16,
  requireSpecial: true
});

// Configure MFA
await settings.requireMfa();      // Required for all
await settings.makeMfaOptional(); // Optional
await settings.disableMfa();      // Disabled

// Domain restrictions
await settings.addAllowedDomain('company.com');
await settings.removeAllowedDomain('old-company.com');

// Check security summary
const security = await settings.getSecuritySummary();
console.log(`Password strength: ${security.passwordStrength}`);
console.log(`MFA status: ${security.mfaStatus}`);
```

## Error Handling

```typescript
import { VaultAdminError } from '@vault/admin-sdk';

try {
  await client.getUser('invalid-id');
} catch (error) {
  if (error instanceof VaultAdminError) {
    console.log(`Error ${error.code}: ${error.message}`);
    console.log(`HTTP Status: ${error.statusCode}`);
    
    if (error.statusCode === 404) {
      console.log('User not found');
    } else if (error.statusCode === 403) {
      console.log('Insufficient permissions');
    }
  }
}
```

## API Reference

### VaultAdminClient

Core client with methods for all API endpoints:

**Dashboard**
- `getDashboard()` - Get dashboard statistics
- `getMetrics(query?)` - Get detailed metrics

**Users**
- `listUsers(query?)` - List users with filters
- `createUser(data)` - Create new user
- `getUser(userId)` - Get user details
- `updateUser(userId, data)` - Update user
- `deleteUser(userId)` - Delete user
- `suspendUser(userId, data?)` - Suspend user
- `activateUser(userId)` - Activate user
- `listUserSessions(userId)` - List sessions
- `revokeAllUserSessions(userId)` - Force logout

**Organizations**
- `listOrganizations(query?)` - List organizations
- `getOrganization(orgId)` - Get org details
- `updateOrganization(orgId, data)` - Update org
- `deleteOrganization(orgId)` - Delete org
- `listOrganizationMembers(orgId)` - List members
- `updateOrganizationMember(orgId, userId, data)` - Update role
- `removeOrganizationMember(orgId, userId)` - Remove member
- `listOrganizationInvitations(orgId)` - List invitations
- `cancelInvitation(orgId, invitationId)` - Cancel invite

**Audit Logs**
- `queryAuditLogs(query?)` - Query logs with filters
- `getRecentAuditLogs(limit?)` - Get recent entries
- `getUserAuditLogs(userId, query?)` - Get user logs

**Settings**
- `getSettings()` - Get tenant settings
- `updateSettings(data)` - Update settings

**System**
- `getSystemHealth()` - Get health status

### Helper Managers

- `UserManager` - User lifecycle and statistics
- `OrganizationManager` - Organization administration
- `AuditManager` - Audit log querying and analysis
- `SettingsManager` - Tenant configuration

## Types

All TypeScript types are exported:

```typescript
import type { 
  AdminUserResponse, 
  AdminOrganizationResponse,
  AuditLogEntry,
  TenantSettings 
} from '@vault/admin-sdk';
```

## License

MIT
