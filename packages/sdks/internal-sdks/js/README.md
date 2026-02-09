# Vault Internal API SDK

TypeScript SDK for the Vault Internal API. Designed for SaaS platform services, internal tools, and automation.

## Installation

```bash
npm install @fantasticauth/internal-sdk
# or
yarn add @fantasticauth/internal-sdk
# or
pnpm add @fantasticauth/internal-sdk
```

## Quick Start

```typescript
import { VaultInternalClient, TenantManager } from '@fantasticauth/internal-sdk';

const client = new VaultInternalClient({
  baseUrl: 'https://api.vault.dev/api/v1/internal',
  apiKey: process.env.VAULT_INTERNAL_API_KEY!
});

// Provision a new tenant during signup
const tenants = new TenantManager(client);
const { tenant, dashboardUrl } = await tenants.provision({
  name: 'Acme Corp',
  ownerEmail: 'admin@acme.com',
  plan: 'pro'
});

console.log(`Tenant created: ${tenant.id}`);
console.log(`Dashboard: ${dashboardUrl}`);
```

## Authentication

The Internal API requires an API key with appropriate scopes:

```typescript
const client = new VaultInternalClient({
  baseUrl: 'https://api.vault.dev/api/v1/internal',
  apiKey: 'vault_internal_xxx',
  timeout: 30000 // optional, default 30s
});
```

**Security Note:** Internal API keys should never be exposed to client browsers. Use them only in server-side code or secure microservices.

## Usage Guide

### Tenant Management

```typescript
import { TenantManager } from '@fantasticauth/internal-sdk';

const tenants = new TenantManager(client);

// Provision new tenant
const result = await tenants.provision({
  name: 'Acme Corp',
  slug: 'acme-corp', // auto-generated if not provided
  ownerEmail: 'admin@acme.com',
  plan: 'pro',
  customDomain: 'auth.acme.com'
});

// Find tenant by slug
const tenant = await tenants.findBySlug('acme-corp');

// Upgrade plan
await tenants.upgradePlan(tenant.id, 'enterprise');

// Update limits
await tenants.setLimits(tenant.id, {
  maxUsers: 500,
  maxOrganizations: 50
});

// Get trials expiring soon
const expiringTrials = await tenants.getTrialsExpiringSoon(7);
```

### Billing & Subscriptions

```typescript
import { BillingManager } from '@fantasticauth/internal-sdk';

const billing = new BillingManager(client);

// Change plan
await billing.changePlan(tenantId, {
  plan: 'enterprise',
  seats: 100,
  interval: 'annual'
});

// Add/remove seats
await billing.addSeats(tenantId, 10);
await billing.removeSeats(tenantId, 5);

// Generate one-time invoice
await billing.chargeOneTime(tenantId, 500, 'Professional services');

// Handle Stripe webhooks
app.post('/webhooks/stripe', async (req, res) => {
  await billing.processStripeWebhook(req.body);
  res.sendStatus(200);
});

// Calculate MRR
const { mrr, arr } = await billing.calculateMRR();
console.log(`MRR: $${mrr}, ARR: $${arr}`);
```

### Platform Analytics

```typescript
import { AnalyticsManager } from '@fantasticauth/internal-sdk';

const analytics = new AnalyticsManager(client);

// Get platform overview
const overview = await analytics.getOverview();
console.log(`Total tenants: ${overview.tenants.total}`);
console.log(`MRR: $${overview.revenue.mrr}`);

// Growth metrics
const growth = await analytics.getGrowthMetrics(
  new Date('2024-01-01'),
  new Date('2024-01-31')
);
console.log(`Growth rate: ${growth.growthRate}%`);

// Usage reports
const apiUsage = await analytics.getUsageReport('apiCalls');
console.log(`Total API calls: ${apiUsage.total}`);
console.log('Top tenants:', apiUsage.topTenants);

// System health
const health = await analytics.getSystemHealth();
if (health.status !== 'healthy') {
  await alertOpsTeam(health);
}
```

### Feature Flags

```typescript
import { FeatureFlagManager } from '@fantasticauth/internal-sdk';

const features = new FeatureFlagManager(client);

// Create feature flag
await features.create('new_dashboard', 'New Dashboard UI', {
  description: 'Enable the new dashboard design',
  enabled: false
});

// Gradual rollout (10% of tenants)
await features.configureRollout('new_dashboard', {
  percentage: 10
});

// Enable for specific tenants
await features.enableForTenants('new_dashboard', ['tenant-1', 'tenant-2']);

// Check if enabled for tenant
const isEnabled = await features.isEnabled('new_dashboard', tenantId);

// Enable globally
await features.enable('new_dashboard');
```

### Support & User Management

```typescript
// Search user across all tenants
const users = await client.searchUsers({ email: 'user@example.com' });

// Get user details with all memberships
const user = await client.getUser(userId);
console.log('Tenants:', user.tenants);

// Impersonate user for support (heavily audited)
const { token } = await client.impersonateUser(userId, {
  tenantId: 'tenant-1',
  duration: 3600, // 1 hour max
  reason: 'Debugging login issue #1234'
});
```

### Maintenance Operations

```typescript
// Run migrations across all tenants
const result = await client.runMigrations({ dryRun: true });
for (const r of result.results) {
  console.log(`${r.tenantId}: ${r.status}`);
}

// Trigger backup
const backup = await client.triggerBackup({
  tenantId: 'tenant-1', // omit for all tenants
  type: 'full'
});
console.log(`Backup job: ${backup.jobId}`);
```

## Error Handling

```typescript
import { VaultInternalError } from '@fantasticauth/internal-sdk';

try {
  await client.createTenant({ name: 'Test', slug: 'test' });
} catch (error) {
  if (error instanceof VaultInternalError) {
    console.log(`Error ${error.code}: ${error.message}`);
    console.log(`HTTP Status: ${error.statusCode}`);
    console.log('Details:', error.details);
  }
}
```

## API Reference

### VaultInternalClient

Core client with methods for all API endpoints:

- `listTenants()`, `getTenant()`, `createTenant()`, `updateTenant()`, `deleteTenant()`
- `suspendTenant()`, `activateTenant()`, `migrateTenant()`
- `searchUsers()`, `getUser()`, `impersonateUser()`
- `listSubscriptions()`, `getSubscription()`, `updateSubscription()`, `generateInvoice()`
- `getPlatformOverview()`, `getTenantAnalytics()`, `getUsageAnalytics()`
- `listFeatureFlags()`, `createFeatureFlag()`, `updateFeatureFlag()`
- `listOAuthProviders()`, `addOAuthProvider()`
- `runMigrations()`, `triggerBackup()`

### Helper Managers

Higher-level abstractions for common operations:

- `TenantManager` - Provisioning, lookups, plan management
- `BillingManager` - Subscriptions, invoicing, webhooks
- `AnalyticsManager` - Reports, metrics, health checks
- `FeatureFlagManager` - Feature flags with caching

## Types

All TypeScript types are exported:

```typescript
import type { 
  Tenant, 
  Subscription, 
  PlatformOverview,
  FeatureFlag 
} from '@fantasticauth/internal-sdk';
```

## License

MIT
