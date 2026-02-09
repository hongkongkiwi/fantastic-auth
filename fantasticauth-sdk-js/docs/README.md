# Vault React SDK Documentation

Complete documentation for the Vault React SDK - a comprehensive authentication and user management solution for React applications.

## Overview

The Vault React SDK provides a complete set of tools for implementing authentication in your React applications:

- **Pre-built Components**: Drop-in UI components for sign-in, sign-up, user management, and more
- **React Hooks**: Powerful hooks for accessing auth state and performing actions
- **TypeScript Support**: Fully typed for the best developer experience
- **SSR Compatible**: Works seamlessly with Next.js and server-side rendering
- **Customizable**: Extensive theming and customization options

## Quick Navigation

### Getting Started
- [Installation](./installation.md) - Install and configure the SDK
- [Getting Started](./getting-started.md) - 5-minute quickstart guide
- [Configuration](./configuration.md) - Complete configuration reference

### Components
- [Components Overview](./components/README.md) - Introduction to all components
- [SignIn](./components/sign-in.md) - Authentication form component
- [SignUp](./components/sign-up.md) - Registration form component
- [UserButton](./components/user-button.md) - User menu with avatar
- [UserProfile](./components/user-profile.md) - Profile management page
- [OrganizationSwitcher](./components/organization-switcher.md) - Organization selection
- [Protect](./components/protect.md) - Route protection component
- [MFAForm](./components/mfa-form.md) - Multi-factor authentication
- [WebAuthnButton](./components/webauthn-button.md) - Passkey authentication

### Hooks
- [Hooks Overview](./hooks/README.md) - Introduction to all hooks
- [useAuth](./hooks/use-auth.md) - Primary authentication hook
- [useUser](./hooks/use-user.md) - User data and management
- [useSession](./hooks/use-session.md) - Session management
- [useSignIn](./hooks/use-sign-in.md) - Sign-in operations
- [useSignUp](./hooks/use-sign-up.md) - Sign-up operations
- [useMfa](./hooks/use-mfa.md) - MFA management
- [useWebAuthn](./hooks/use-webauthn.md) - Passkey operations
- [useOrganization](./hooks/use-organization.md) - Organization management

### Theming
- [Theming Overview](./theming/README.md) - Introduction to theming
- [Customization](./theming/customization.md) - Customize component appearance
- [CSS Variables](./theming/css-variables.md) - Complete CSS variables reference

### Examples
- [Next.js App Router](./examples/nextjs-app-router.md) - Next.js 13+ setup
- [Next.js Pages Router](./examples/nextjs-pages-router.md) - Next.js legacy setup
- [React SPA](./examples/react-spa.md) - Single page application
- [Protected Routes](./examples/protected-routes.md) - Route protection patterns
- [Organizations](./examples/organizations.md) - B2B multi-tenancy

### Migration Guides
- [From Clerk](./migration/from-clerk.md) - Migrate from Clerk
- [From Auth0](./migration/from-auth0.md) - Migrate from Auth0
- [From Firebase](./migration/from-firebase.md) - Migrate from Firebase Auth

## Installation

```bash
npm install @vault/react
```

## Quick Start

```tsx
import { VaultProvider, SignIn, useAuth, UserButton } from '@vault/react';

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

function YourApp() {
  const { isSignedIn } = useAuth();
  
  return isSignedIn ? <UserButton /> : <SignIn />;
}
```

## Key Features

- 🔐 **Multiple Auth Methods**: Email/password, magic links, OAuth, WebAuthn/passkeys
- 🛡️ **Enterprise Security**: MFA/TOTP, session management, secure tokens
- 🏢 **Organizations**: Multi-tenant support with role-based access
- ⚛️ **React Native**: Hooks and patterns that work across platforms
- 🎨 **Fully Customizable**: Override any part of the UI
- 📱 **Responsive**: Mobile-friendly components
- 🔍 **Accessible**: ARIA labels, keyboard navigation, screen reader support

## Support

- [GitHub Issues](https://github.com/vault/auth/issues)
- [Discord Community](https://discord.gg/vault)
- [Email Support](mailto:support@vault.dev)

## License

MIT © Vault Team
