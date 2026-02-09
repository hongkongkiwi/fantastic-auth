# @fantasticauth/react

[![npm version](https://badge.fury.io/js/@vault%2Freact.svg)](https://www.npmjs.com/package/@fantasticauth/react)
[![build](https://github.com/vault/auth/actions/workflows/build.yml/badge.svg)](https://github.com/vault/auth/actions)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0-blue.svg)](https://www.typescriptlang.org/)
[![React](https://img.shields.io/badge/React-16.8+-61DAFB.svg?logo=react)](https://reactjs.org/)

A comprehensive React SDK for Vault authentication and user management.

## Features

- 🔐 **Complete Authentication** - Sign in/up with email/password, magic links, OAuth, and WebAuthn/passkeys
- 👤 **User Management** - Profile management, password changes, account deletion
- 🛡️ **Security** - MFA/TOTP support, session management, route protection
- 🏢 **Organizations** - Multi-tenant organization support with role-based access
- ⚛️ **React Integration** - Hooks, context, and pre-built components
- 📱 **SSR Compatible** - Works with Next.js and server-side rendering
- 🎨 **Customizable** - Headless components with theme support
- 🔍 **Accessible** - ARIA labels, keyboard navigation, screen reader support

## Installation

```bash
npm install @fantasticauth/react
# or
yarn add @fantasticauth/react
# or
pnpm add @fantasticauth/react
```

## Quick Start

### 1. Wrap your app with `VaultProvider`

```tsx
import { VaultProvider } from '@fantasticauth/react';

function App() {
  return (
    <VaultProvider
      config={{
        apiUrl: 'https://api.vault.dev',
        tenantId: 'your-tenant-id',
      }}
    >
      <YourApp />
    </VaultProvider>
  );
}
```

### 2. Add authentication to your app

```tsx
import { useAuth, SignIn, SignedIn, SignedOut, UserButton } from '@fantasticauth/react';

function Header() {
  return (
    <header>
      <SignedIn>
        <UserButton />
      </SignedIn>
      <SignedOut>
        <a href="/sign-in">Sign In</a>
      </SignedOut>
    </header>
  );
}

function SignInPage() {
  return (
    <SignIn
      oauthProviders={['google', 'github']}
      showMagicLink={true}
      redirectUrl="/dashboard"
    />
  );
}
```

## Documentation

- [Getting Started](./docs/getting-started.md) - 5-minute quickstart
- [Installation](./docs/installation.md) - Detailed installation guide
- [Configuration](./docs/configuration.md) - SDK configuration reference
- [Components](./docs/components/README.md) - Pre-built components
- [Hooks](./docs/hooks/README.md) - React hooks reference
- [Theming](./docs/theming/README.md) - Customize appearance

### Examples

- [Next.js App Router](./docs/examples/nextjs-app-router.md)
- [Next.js Pages Router](./docs/examples/nextjs-pages-router.md)
- [React SPA](./docs/examples/react-spa.md)
- [Protected Routes](./docs/examples/protected-routes.md)

### Migration Guides

- [From Clerk](./docs/migration/from-clerk.md)
- [From Auth0](./docs/migration/from-auth0.md)
- [From Firebase](./docs/migration/from-firebase.md)

## Components

### Authentication

| Component | Description |
|-----------|-------------|
| `<SignIn />` | Complete sign-in form |
| `<SignUp />` | Registration form |
| `<MFAForm />` | MFA verification |
| `<WebAuthnButton />` | Passkey sign-in |

### User Management

| Component | Description |
|-----------|-------------|
| `<UserButton />` | User avatar with dropdown |
| `<UserProfile />` | Profile management |

### Utilities

| Component | Description |
|-----------|-------------|
| `<Protect />` | Route protection |
| `<SignedIn />` | Conditional rendering (signed in) |
| `<SignedOut />` | Conditional rendering (signed out) |

## Hooks

| Hook | Description |
|------|-------------|
| `useAuth()` | Authentication state and actions |
| `useUser()` | Current user data |
| `useSession()` | Session and token management |
| `useSignIn()` | Sign-in with loading/error states |
| `useSignUp()` | Sign-up with loading/error states |
| `useMfa()` | MFA setup and verification |
| `useOrganization()` | Organization management |

## Theming

Customize the look and feel:

```tsx
<SignIn
  appearance={{
    theme: 'light',
    variables: {
      colorPrimary: '#6366f1',
      borderRadius: '8px',
    },
  }}
/>
```

## TypeScript

Full TypeScript support:

```tsx
import type { User, Session, SignInProps } from '@fantasticauth/react';
```

## Framework Support

- ✅ React 16.8+
- ✅ Next.js (App Router & Pages Router)
- ✅ Remix
- ✅ Gatsby
- ✅ Create React App
- ✅ Vite

## Browser Support

- Chrome 80+
- Firefox 75+
- Safari 13.1+
- Edge 80+

## Contributing

We welcome contributions! Please see our [Contributing Guide](./CONTRIBUTING.md) for details.

## License

[MIT](./LICENSE) © Vault Team

## Support

- [Documentation](https://docs.vault.dev)
- [GitHub Issues](https://github.com/vault/auth/issues)
- [Discord Community](https://discord.gg/vault)
- [Email Support](mailto:support@vault.dev)
