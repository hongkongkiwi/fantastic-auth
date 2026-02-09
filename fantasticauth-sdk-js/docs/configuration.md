# Configuration

Complete reference for configuring the Vault React SDK.

## VaultProvider Configuration

The `VaultProvider` accepts a `config` object with the following properties:

```tsx
import { VaultProvider } from '@vault/react';

<VaultProvider
  config={{
    apiUrl: 'https://api.vault.dev',
    tenantId: 'your-tenant-id',
    debug: false,
    turnstileSiteKey: 'your-turnstile-key',
  }}
>
  <YourApp />
</VaultProvider>
```

## Configuration Options

### Required Options

| Option | Type | Description |
|--------|------|-------------|
| `apiUrl` | `string` | The Vault API endpoint URL |
| `tenantId` | `string` | Your unique tenant identifier |

### Optional Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `debug` | `boolean` | `false` | Enable debug logging |
| `sessionToken` | `string` | - | Initial session token (for SSR) |
| `fetch` | `typeof fetch` | `global.fetch` | Custom fetch implementation |
| `turnstileSiteKey` | `string` | - | Turnstile site key for bot protection |
| `oauth` | `object` | - | OAuth provider configuration |

## Configuration Reference

### Basic Configuration

```tsx
<VaultProvider
  config={{
    apiUrl: 'https://api.vault.dev',
    tenantId: 'your-tenant-id',
  }}
>
  <App />
</VaultProvider>
```

### With Environment Variables

```tsx
<VaultProvider
  config={{
    apiUrl: process.env.NEXT_PUBLIC_VAULT_API_URL!,
    tenantId: process.env.NEXT_PUBLIC_VAULT_TENANT_ID!,
    debug: process.env.NODE_ENV === 'development',
  }}
>
  <App />
</VaultProvider>
```

### With OAuth Configuration

```tsx
<VaultProvider
  config={{
    apiUrl: 'https://api.vault.dev',
    tenantId: 'your-tenant-id',
    oauth: {
      google: { clientId: 'your-google-client-id' },
      github: { clientId: 'your-github-client-id' },
      microsoft: { clientId: 'your-microsoft-client-id' },
    },
  }}
>
  <App />
</VaultProvider>
```

### With Bot Protection

```tsx
<VaultProvider
  config={{
    apiUrl: 'https://api.vault.dev',
    tenantId: 'your-tenant-id',
    turnstileSiteKey: 'your-turnstile-site-key',
  }}
>
  <App />
</VaultProvider>
```

## SSR Configuration

### Next.js App Router

```tsx
// app/providers.tsx
'use client';

import { VaultProvider } from '@vault/react';

interface ProvidersProps {
  children: React.ReactNode;
  initialUser?: User;
  initialSessionToken?: string;
}

export function Providers({ children, initialUser, initialSessionToken }: ProvidersProps) {
  return (
    <VaultProvider
      config={{
        apiUrl: process.env.NEXT_PUBLIC_VAULT_API_URL!,
        tenantId: process.env.NEXT_PUBLIC_VAULT_TENANT_ID!,
        sessionToken: initialSessionToken,
      }}
    >
      {children}
    </VaultProvider>
  );
}
```

### Next.js Pages Router

```tsx
// pages/_app.tsx
import { VaultProvider } from '@vault/react';
import type { AppProps } from 'next/app';

export default function MyApp({ Component, pageProps }: AppProps) {
  return (
    <VaultProvider
      config={{
        apiUrl: process.env.NEXT_PUBLIC_VAULT_API_URL!,
        tenantId: process.env.NEXT_PUBLIC_VAULT_TENANT_ID!,
      }}
      initialUser={pageProps.user}
      initialSessionToken={pageProps.sessionToken}
    >
      <Component {...pageProps} />
    </VaultProvider>
  );
}
```

## TypeScript Configuration

### Type Augmentation

If you need to extend the User type:

```tsx
// types/vault.d.ts
import '@vault/react';

declare module '@vault/react' {
  interface User {
    customField?: string;
    preferences?: {
      theme: 'light' | 'dark';
    };
  }
}
```

### Strict TypeScript

Enable strict mode for best type safety:

```json
// tsconfig.json
{
  "compilerOptions": {
    "strict": true,
    "noImplicitAny": true,
    "strictNullChecks": true
  }
}
```

## Environment Variables

### Development

```bash
# .env.development
NEXT_PUBLIC_VAULT_API_URL=https://api.vault.dev
NEXT_PUBLIC_VAULT_TENANT_ID=dev-tenant-id
```

### Production

```bash
# .env.production
NEXT_PUBLIC_VAULT_API_URL=https://api.vault.io
NEXT_PUBLIC_VAULT_TENANT_ID=prod-tenant-id
```

### Local

```bash
# .env.local (not committed)
NEXT_PUBLIC_VAULT_TENANT_ID=your-local-tenant
```

## Advanced Configuration

### Custom Fetch Implementation

Useful for adding request interceptors:

```tsx
const customFetch = async (url: string, options: RequestInit = {}) => {
  // Add custom headers
  const headers = {
    ...options.headers,
    'X-Custom-Header': 'value',
  };

  // Add request logging
  console.log(`[API] ${options.method || 'GET'} ${url}`);

  return fetch(url, { ...options, headers });
};

<VaultProvider
  config={{
    apiUrl: 'https://api.vault.dev',
    tenantId: 'your-tenant-id',
    fetch: customFetch,
  }}
>
  <App />
</VaultProvider>
```

### Debug Mode

Enable debug mode to see detailed logs:

```tsx
<VaultProvider
  config={{
    apiUrl: 'https://api.vault.dev',
    tenantId: 'your-tenant-id',
    debug: true,
  }}
>
  <App />
</VaultProvider>
```

Debug mode logs:
- API requests and responses
- Authentication state changes
- Session management events
- Error details

### Multiple Environments

Create a configuration factory:

```tsx
// config/vault.ts
interface VaultConfigFactory {
  environment: 'development' | 'staging' | 'production';
}

export function createVaultConfig({ environment }: VaultConfigFactory) {
  const configs = {
    development: {
      apiUrl: 'http://localhost:8080',
      tenantId: 'dev-tenant',
      debug: true,
    },
    staging: {
      apiUrl: 'https://staging-api.vault.dev',
      tenantId: 'staging-tenant',
      debug: true,
    },
    production: {
      apiUrl: 'https://api.vault.io',
      tenantId: 'prod-tenant',
      debug: false,
    },
  };

  return configs[environment];
}

// Usage
<VaultProvider
  config={createVaultConfig({ environment: process.env.NODE_ENV as any })}
>
  <App />
</VaultProvider>
```

## Error Handling

### Global Error Handler

```tsx
<VaultProvider
  config={{
    apiUrl: 'https://api.vault.dev',
    tenantId: 'your-tenant-id',
  }}
  onAuthStateChange={(state) => {
    if (state.status === 'error') {
      console.error('Auth error:', state.error);
      // Send to error tracking service
      Sentry.captureException(state.error);
    }
  }}
>
  <App />
</VaultProvider>
```

## Configuration Validation

Validate your configuration at runtime:

```tsx
import { VaultProvider, VaultConfig } from '@vault/react';

function validateConfig(config: VaultConfig): void {
  if (!config.apiUrl) {
    throw new Error('VAULT_API_URL is required');
  }
  
  if (!config.tenantId) {
    throw new Error('VAULT_TENANT_ID is required');
  }
  
  try {
    new URL(config.apiUrl);
  } catch {
    throw new Error(`Invalid VAULT_API_URL: ${config.apiUrl}`);
  }
}

const config: VaultConfig = {
  apiUrl: process.env.VAULT_API_URL!,
  tenantId: process.env.VAULT_TENANT_ID!,
};

validateConfig(config);

<VaultProvider config={config}>
  <App />
</VaultProvider>
```

## Complete Configuration Example

```tsx
import { VaultProvider } from '@vault/react';

const config = {
  // Required
  apiUrl: process.env.NEXT_PUBLIC_VAULT_API_URL!,
  tenantId: process.env.NEXT_PUBLIC_VAULT_TENANT_ID!,

  // Optional - Development
  debug: process.env.NODE_ENV === 'development',

  // Optional - Bot Protection
  turnstileSiteKey: process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY,

  // Optional - OAuth
  oauth: {
    google: { clientId: process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID! },
    github: { clientId: process.env.NEXT_PUBLIC_GITHUB_CLIENT_ID! },
  },

  // Optional - Custom fetch
  fetch: async (url, options) => {
    const response = await fetch(url, options);
    
    // Log API calls in development
    if (process.env.NODE_ENV === 'development') {
      console.log(`[Vault API] ${response.status} ${url}`);
    }
    
    return response;
  },
};

export function App({ children, initialUser, initialSessionToken }) {
  return (
    <VaultProvider
      config={config}
      initialUser={initialUser}
      initialSessionToken={initialSessionToken}
      onAuthStateChange={(state) => {
        if (state.status === 'error') {
          console.error('Auth error:', state.error);
        }
      }}
    >
      {children}
    </VaultProvider>
  );
}
```

## See Also

- [Getting Started](./getting-started.md) - Quickstart guide
- [TypeScript Types](./hooks/use-auth.md#types) - Type definitions
- [SSR Examples](./examples/nextjs-app-router.md) - Server-side rendering
