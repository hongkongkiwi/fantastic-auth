# Vault React UI

Pre-built React UI components for Vault authentication. This package provides ready-to-use, customizable authentication components that work seamlessly with the Vault platform.

## Features

- 🎨 **Pre-built Components** - Ready-to-use login, signup, password reset, and MFA forms
- 🌙 **Dark Mode Support** - Built-in light, dark, and auto themes
- ♿ **Accessible** - ARIA labels, keyboard navigation, and screen reader support
- 📱 **Responsive** - Mobile-first design that works on all devices
- 🎯 **TypeScript** - Full TypeScript support with comprehensive type definitions
- 🎨 **Customizable** - CSS variables for easy theming
- 🔒 **Secure** - Built on top of the Vault React SDK

## Installation

```bash
npm install @fantasticauth/react-ui
# or
yarn add @fantasticauth/react-ui
# or
pnpm add @fantasticauth/react-ui
```

## Quick Start

### 1. Wrap your app with VaultAuthProvider

```tsx
import { VaultAuthProvider } from '@fantasticauth/react-ui';

function App() {
  return (
    <VaultAuthProvider
      apiKey="your-api-key"
      baseUrl="https://api.vault.dev"
      defaultTheme="auto"
    >
      <YourApp />
    </VaultAuthProvider>
  );
}
```

### 2. Use the components

```tsx
import { LoginForm, useAuth, UserProfile } from '@fantasticauth/react-ui';

function YourApp() {
  const { isAuthenticated, user, logout } = useAuth();

  if (!isAuthenticated) {
    return (
      <LoginForm
        onSuccess={(user) => console.log('Logged in:', user)}
        onError={(error) => console.error('Login failed:', error)}
        socialProviders={['google', 'github']}
        enableMagicLink
      />
    );
  }

  return (
    <div>
      <h1>Welcome, {user?.email}</h1>
      <UserProfile showChangePassword showDeleteAccount />
      <button onClick={logout}>Sign out</button>
    </div>
  );
}
```

## Components

### LoginForm

A complete login form with email/password, social login, and magic link support.

```tsx
import { LoginForm } from '@fantasticauth/react-ui';

<LoginForm
  onSuccess={(user) => console.log('Logged in:', user)}
  onError={(error) => console.error('Error:', error)}
  redirectUrl="/dashboard"
  showSignupLink={true}
  showForgotPassword={true}
  socialProviders={['google', 'github', 'microsoft']}
  enableMagicLink={true}
  theme="auto"
/>
```

### SignupForm

User registration form with customizable fields and social signup.

```tsx
import { SignupForm } from '@fantasticauth/react-ui';

<SignupForm
  onSuccess={(user) => console.log('Signed up:', user)}
  onError={(error) => console.error('Error:', error)}
  requireEmailVerification={true}
  allowedDomains={['company.com']}
  fields={['name', 'phone', 'organization']}
  termsUrl="/terms"
  privacyUrl="/privacy"
  socialProviders={['google', 'github']}
/>
```

### PasswordResetForm

Password reset form with request and completion states.

```tsx
import { PasswordResetForm } from '@fantasticauth/react-ui';

// Request reset
<PasswordResetForm onSuccess={() => console.log('Email sent')} />

// Complete reset (with token from URL)
<PasswordResetForm
  token={resetToken}
  onSuccess={() => console.log('Password reset')}
  redirectUrl="/login"
/>
```

### MFASetup

Multi-factor authentication setup component.

```tsx
import { MFASetup } from '@fantasticauth/react-ui';

<MFASetup
  methods={['totp', 'sms', 'email']}
  onSuccess={() => console.log('MFA enabled')}
  onError={(error) => console.error('Error:', error)}
  onCancel={() => console.log('Cancelled')}
/>
```

### UserProfile

User profile management with edit, password change, and account deletion.

```tsx
import { UserProfile } from '@fantasticauth/react-ui';

<UserProfile
  onUpdate={(user) => console.log('Updated:', user)}
  onError={(error) => console.error('Error:', error)}
  showChangePassword={true}
  showDeleteAccount={true}
/>
```

### OrganizationSwitcher

Organization switching and creation dropdown.

```tsx
import { OrganizationSwitcher } from '@fantasticauth/react-ui';

<OrganizationSwitcher
  hidePersonal={false}
  onSwitch={(org) => console.log('Switched to:', org)}
  onCreate={() => console.log('Creating new org')}
/>
```

### SessionList

Active session management with device information.

```tsx
import { SessionList } from '@fantasticauth/react-ui';

<SessionList
  onRevoke={(sessionId) => console.log('Revoked:', sessionId)}
  onRevokeAll={() => console.log('Revoked all')}
  showDeviceInfo={true}
  showLocation={true}
/>
```

## Hooks

### useAuth

Main authentication hook with login, logout, signup, and password reset.

```tsx
import { useAuth } from '@fantasticauth/react-ui';

function MyComponent() {
  const { 
    user, 
    isLoading, 
    isAuthenticated, 
    login, 
    logout, 
    signup,
    resetPassword,
    error,
    clearError 
  } = useAuth();

  const handleLogin = async (email: string, password: string) => {
    try {
      await login({ email, password });
    } catch (error) {
      console.error('Login failed:', error);
    }
  };

  return <div>{isAuthenticated ? `Hello ${user?.email}` : 'Please sign in'}</div>;
}
```

### useUser

User profile management hook.

```tsx
import { useUser } from '@fantasticauth/react-ui';

function ProfileComponent() {
  const { user, update, changePassword, deleteAccount, isLoading } = useUser();

  const handleUpdate = async (updates) => {
    await update(updates);
  };

  return <div>{user?.email}</div>;
}
```

### useOrganization

Organization management hook.

```tsx
import { useOrganization, useIsOrgAdmin } from '@fantasticauth/react-ui';

function OrgComponent() {
  const { 
    organization, 
    organizations, 
    setActive, 
    create, 
    leave 
  } = useOrganization();
  
  const isAdmin = useIsOrgAdmin();

  return (
    <div>
      <p>Active: {organization?.name}</p>
      <p>Admin: {isAdmin ? 'Yes' : 'No'}</p>
    </div>
  );
}
```

## Theming

### CSS Variables

Customize the appearance using CSS variables:

```css
:root {
  --vault-primary: #3b82f6;
  --vault-primary-hover: #2563eb;
  --vault-error: #ef4444;
  --vault-success: #10b981;
  --vault-background: #ffffff;
  --vault-text: #1f2937;
  --vault-border: #e5e7eb;
  --vault-border-radius: 8px;
  --vault-font-family: system-ui, -apple-system, sans-serif;
}
```

### Theme Modes

Three theme modes are supported:

```tsx
// Light theme
<VaultAuthProvider defaultTheme="light">...</VaultAuthProvider>

// Dark theme
<VaultAuthProvider defaultTheme="dark">...</VaultAuthProvider>

// Auto (follows system preference)
<VaultAuthProvider defaultTheme="auto">...</VaultAuthProvider>
```

### Custom Theme Variables

```tsx
<VaultAuthProvider
  apiKey="your-api-key"
  baseUrl="https://api.vault.dev"
  themeVariables={{
    primary: '#6366f1',
    primaryHover: '#4f46e5',
    borderRadius: '12px',
    fontFamily: 'Inter, sans-serif',
  }}
>
  ...
</VaultAuthProvider>
```

### Per-Component Theming

Individual components can also specify their theme:

```tsx
<LoginForm theme="dark" />
<SignupForm theme="light" />
```

## Styling

### Default CSS

Import the default styles:

```tsx
import '@fantasticauth/react-ui/styles.css';
```

### Custom Styling

All components use BEM-style class names for easy customization:

```css
/* Custom login form styling */
.vault-login-form {
  max-width: 400px;
  margin: 0 auto;
}

.vault-login-title {
  font-size: 1.5rem;
  font-weight: 600;
}

.vault-btn-primary {
  background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
}
```

## Accessibility

All components are built with accessibility in mind:

- Full keyboard navigation support
- ARIA labels and roles
- Focus management
- Screen reader announcements for errors and success states
- High contrast mode support
- Reduced motion support

## TypeScript

Full TypeScript support is included:

```tsx
import type { 
  LoginFormProps, 
  UseAuthReturn, 
  User,
  AuthError 
} from '@fantasticauth/react-ui';
```

## Browser Support

- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+

## License

MIT

## Support

For support, please visit [Vault Documentation](https://docs.vault.dev) or contact support@vault.dev.
