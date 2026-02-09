# Vault Internal SDK Guide

## Package Structure

```
vault-sdk-js-internal/
├── src/
│   ├── index.ts              # Main exports
│   ├── client.ts             # Core HTTP client
│   ├── tenants.ts            # Tenant manager helper
│   ├── billing.ts            # Billing manager helper
│   ├── analytics.ts          # Analytics manager helper
│   ├── features.ts           # Feature flag manager helper
│   └── generated/
│       └── client.ts         # Auto-generated types
├── examples/
│   ├── tenant-signup.ts      # SaaS signup flow example
│   ├── webhook-handler.ts    # Stripe webhook handler
│   └── feature-flags.ts      # Feature flag management
├── package.json
├── tsconfig.json
└── README.md
```

## Key Features

### 1. Type-Safe API Client

All API endpoints are fully typed:

```typescript
const client = new VaultInternalClient({
  baseUrl: 'https://api.vault.dev/api/v1/internal',
  apiKey: 'vault_internal_xxx'
});

// Full autocomplete and type checking
const tenant: Tenant = await client.createTenant({
  name: 'Acme Corp',
  slug: 'acme-corp'
});
```

### 2. Helper Managers

High-level abstractions for common operations:

- **TenantManager** - Provisioning, lookups, plan changes
- **BillingManager** - Subscriptions, invoicing, MRR calculation
- **AnalyticsManager** - Reports, growth metrics, health checks
- **FeatureFlagManager** - Rollouts with local caching

### 3. Error Handling

Custom error class with detailed information:

```typescript
import { VaultInternalError } from '@fantasticauth/internal-sdk';

try {
  await client.createTenant({ ... });
} catch (error) {
  if (error instanceof VaultInternalError) {
    console.log(error.code);      // 'SLUG_TAKEN'
    console.log(error.statusCode); // 409
    console.log(error.message);    // 'Tenant slug already exists'
  }
}
```

### 4. Request Timeouts

Configurable timeouts with automatic abort:

```typescript
const client = new VaultInternalClient({
  baseUrl: '...',
  apiKey: '...',
  timeout: 10000 // 10 seconds
});

// Or per-request
await client.createTenant(data, { timeout: 5000 });
```

## Usage Patterns

### SaaS Signup Flow

```typescript
import { VaultInternalClient, TenantManager } from '@fantasticauth/internal-sdk';

const client = new VaultInternalClient({...});
const tenants = new TenantManager(client);

// In your signup endpoint
app.post('/signup', async (req, res) => {
  const { companyName, email, plan } = req.body;
  
  const { tenant, dashboardUrl } = await tenants.provision({
    name: companyName,
    ownerEmail: email,
    plan
  });
  
  // Send welcome email with dashboardUrl
  res.json({ tenantId: tenant.id, dashboardUrl });
});
```

### Feature Flag Evaluation

```typescript
import { FeatureFlagManager } from '@fantasticauth/internal-sdk';

const features = new FeatureFlagManager(client);

// In your middleware
app.use(async (req, res, next) => {
  const tenantId = req.headers['x-tenant-id'];
  
  // Check if feature is enabled (with 1min cache)
  const isEnabled = await features.isEnabled('new_ui', tenantId);
  res.locals.useNewUi = isEnabled;
  
  next();
});
```

### Billing Webhooks

```typescript
import { BillingManager } from '@fantasticauth/internal-sdk';

const billing = new BillingManager(client);

app.post('/webhooks/stripe', async (req, res) => {
  await billing.processStripeWebhook(req.body);
  res.sendStatus(200);
});
```

## Environment Variables

```bash
# Required
VAULT_API_URL=https://api.vault.dev/api/v1/internal
VAULT_INTERNAL_API_KEY=vault_internal_xxx

# Optional
VAULT_REQUEST_TIMEOUT=30000
```

## Security Best Practices

1. **Never expose API keys in client-side code**
   - Use only in server-side applications
   - Store in environment variables

2. **IP Restrict internal API**
   - Restrict `/api/v1/internal/*` to internal services only
   - Use VPC or internal network

3. **Audit sensitive operations**
   - All Internal API calls are logged
   - Impersonation requires reason and is heavily audited

4. **Use least-privilege keys**
   - Create separate API keys for different services
   - Scope keys to specific endpoints if possible

## Generating Types

To regenerate types from OpenAPI spec:

```bash
cd vault-sdk-js-internal
npm run generate
```

This runs:
```bash
openapi-typescript ../../openapi/vault-internal-api.yaml -o src/generated/client.ts
```

## Publishing

```bash
npm run build
npm publish --access restricted
```
