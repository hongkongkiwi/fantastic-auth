# Installation

This guide covers all the ways to install and set up the Vault React SDK in your project.

## Prerequisites

- React 16.8+ (hooks support)
- TypeScript 4.5+ (recommended)
- A Vault account and tenant ID

## Package Installation

### npm

```bash
npm install @fantasticauth/react
```

### yarn

```bash
yarn add @fantasticauth/react
```

### pnpm

```bash
pnpm add @fantasticauth/react
```

## Peer Dependencies

The SDK requires React as a peer dependency:

```bash
npm install react react-dom
```

## Framework-Specific Setup

### Next.js

For Next.js projects, additional configuration may be needed for SSR:

```bash
npm install @fantasticauth/react
```

Create a provider wrapper:

```tsx
// app/providers.tsx (App Router)
'use client';

import { VaultProvider } from '@fantasticauth/react';

export function Providers({ children }: { children: React.ReactNode }) {
  return (
    <VaultProvider
      config={{
        apiUrl: process.env.NEXT_PUBLIC_VAULT_API_URL!,
        tenantId: process.env.NEXT_PUBLIC_VAULT_TENANT_ID!,
      }}
    >
      {children}
    </VaultProvider>
  );
}
```

See the [Next.js App Router](./examples/nextjs-app-router.md) guide for complete setup.

### Vite

```bash
npm install @fantasticauth/react
```

No additional configuration needed. The SDK works out of the box with Vite.

### Create React App

```bash
npm install @fantasticauth/react
```

Standard setup works without additional configuration.

### Remix

```bash
npm install @fantasticauth/react
```

For Remix, you may want to configure the SDK for server-side rendering:

```tsx
// app/root.tsx
import { VaultProvider } from '@fantasticauth/react';

export default function App() {
  return (
    <VaultProvider
      config={{
        apiUrl: process.env.VAULT_API_URL!,
        tenantId: process.env.VAULT_TENANT_ID!,
      }}
    >
      <Outlet />
    </VaultProvider>
  );
}
```

## Environment Variables

Create a `.env` file in your project root:

```bash
# Vault Configuration
VAULT_API_URL=https://api.vault.dev
VAULT_TENANT_ID=your-tenant-id

# For client-side frameworks (Next.js, etc.)
NEXT_PUBLIC_VAULT_API_URL=https://api.vault.dev
NEXT_PUBLIC_VAULT_TENANT_ID=your-tenant-id
```

## TypeScript Configuration

The SDK includes TypeScript declarations. Ensure your `tsconfig.json` includes:

```json
{
  "compilerOptions": {
    "moduleResolution": "node",
    "esModuleInterop": true,
    "allowSyntheticDefaultImports": true
  }
}
```

## Verify Installation

Create a simple test component:

```tsx
// TestVault.tsx
import { useAuth, SignIn } from '@fantasticauth/react';

export function TestVault() {
  const { isLoaded, isSignedIn } = useAuth();

  if (!isLoaded) {
    return <div>Loading...</div>;
  }

  return (
    <div>
      {isSignedIn ? (
        <p>✅ Vault SDK is working!</p>
      ) : (
        <SignIn />
      )}
    </div>
  );
}
```

## Troubleshooting

### Module not found

If you get a "Module not found" error:

1. Ensure you installed the package: `npm list @fantasticauth/react`
2. Clear your node_modules and reinstall: `rm -rf node_modules && npm install`
3. Check your import path: `import { ... } from '@fantasticauth/react'`

### TypeScript errors

If you see TypeScript errors:

1. Update TypeScript: `npm install typescript@latest`
2. Check your `tsconfig.json` module resolution settings
3. Ensure you have `@types/react` installed

### Build errors

If you encounter build errors:

1. Check for duplicate React versions: `npm ls react`
2. Ensure all peer dependencies are installed
3. Check your bundler configuration for ESM/CJS compatibility

## Next Steps

- [Getting Started Guide](./getting-started.md) - Build your first login flow
- [Configuration](./configuration.md) - Learn about all configuration options
- [Components Overview](./components/README.md) - Explore available components
