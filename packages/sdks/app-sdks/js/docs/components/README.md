# Components Overview

The Vault React SDK provides a complete set of pre-built components for authentication and user management.

## Component Categories

### Authentication Components

Components for handling sign-in, sign-up, and authentication flows.

| Component | Description |
|-----------|-------------|
| [`<SignIn />`](./sign-in.md) | Complete sign-in form with email/password, OAuth, magic links, and WebAuthn |
| [`<SignUp />`](./sign-up.md) | Registration form with email/password and OAuth |
| [`<MFAForm />`](./mfa-form.md) | Multi-factor authentication verification form |
| [`<WebAuthnButton />`](./webauthn-button.md) | Passkey/WebAuthn sign-in button |
| [`<VerifyEmail />`](./verify-email.md) | Email verification handler |
| [`<ResetPassword />`](./reset-password.md) | Password reset form |

### User Components

Components for user management and profile.

| Component | Description |
|-----------|-------------|
| [`<UserButton />`](./user-button.md) | User avatar with dropdown menu |
| [`<UserProfile />`](./user-profile.md) | Profile management page component |

### Organization Components (B2B)

Components for multi-tenant organization management.

| Component | Description |
|-----------|-------------|
| [`<OrganizationSwitcher />`](./organization-switcher.md) | Organization selection dropdown |
| [`<CreateOrganization />`](./create-organization.md) | Create new organization form |
| [`<OrganizationProfile />`](./organization-profile.md) | Organization management page |

### Control Components

Components for conditional rendering based on auth state.

| Component | Description |
|-----------|-------------|
| [`<SignedIn />`](./control-components.md) | Renders children only when signed in |
| [`<SignedOut />`](./control-components.md) | Renders children only when signed out |
| [`<RequireAuth />`](./control-components.md) | Requires authentication with fallback |

### Protection Components

Components for securing routes and content.

| Component | Description |
|-----------|-------------|
| [`<Protect />`](./protect.md) | Route protection with role/permission checks |
| [`<RedirectToSignIn />`](./protect.md) | Redirects to sign-in page |
| [`<RedirectToSignUp />`](./protect.md) | Redirects to sign-up page |

## Common Props

All Vault components accept these common props:

| Prop | Type | Description |
|------|------|-------------|
| `appearance` | `Appearance` | Custom styling configuration |
| `className` | `string` | Additional CSS class names |

### Appearance Prop

The `appearance` prop allows you to customize the look and feel:

```tsx
<SignIn
  appearance={{
    theme: 'light',
    variables: {
      colorPrimary: '#6366f1',
      borderRadius: '8px',
      fontSize: '16px',
    },
    elements: {
      button: { padding: '12px 24px' },
      input: { borderWidth: '2px' },
    },
  }}
/>
```

See the [Theming Guide](../theming/customization.md) for complete customization options.

## Usage Examples

### Basic Authentication Flow

```tsx
import { SignIn, SignUp, useAuth, UserButton } from '@fantasticauth/react';

function App() {
  const { isSignedIn } = useAuth();

  if (isSignedIn) {
    return <UserButton />;
  }

  return (
    <div>
      <SignIn redirectUrl="/dashboard" />
      <p>or</p>
      <a href="/sign-up">Create account</a>
    </div>
  );
}
```

### Conditional Rendering

```tsx
import { SignedIn, SignedOut, UserButton, SignIn } from '@fantasticauth/react';

function Header() {
  return (
    <header>
      <SignedIn>
        <UserButton showName={true} />
      </SignedIn>
      <SignedOut>
        <nav>
          <a href="/sign-in">Sign In</a>
          <a href="/sign-up">Sign Up</a>
        </nav>
      </SignedOut>
    </header>
  );
}
```

### Route Protection

```tsx
import { Protect } from '@fantasticauth/react';

function AdminPage() {
  return (
    <Protect role="admin" fallback={<p>Admin access required</p>}>
      <div>
        <h1>Admin Dashboard</h1>
        {/* Admin-only content */}
      </div>
    </Protect>
  );
}
```

### Multi-Factor Authentication

```tsx
import { MFAForm, useAuth } from '@fantasticauth/react';

function SignInPage() {
  const { authState } = useAuth();

  // Check if MFA is required
  if (authState.status === 'mfa_required') {
    return (
      <MFAForm
        onVerify={() => {
          window.location.href = '/dashboard';
        }}
        allowBackupCode={true}
      />
    );
  }

  return <SignIn />;
}
```

## Component Hierarchy

```
VaultProvider (root context)
├── SignIn / SignUp (auth pages)
│   ├── OAuth buttons
│   ├── Email/password form
│   └── WebAuthn button (optional)
├── MFAForm (when MFA required)
├── UserButton (when authenticated)
│   └── Dropdown menu
├── UserProfile (profile page)
│   ├── Profile tab
│   ├── Security tab
│   └── Danger zone tab
├── OrganizationSwitcher (B2B)
├── Protect (route guards)
├── SignedIn / SignedOut (conditional)
└── RedirectToSignIn / RedirectToSignUp (navigation)
```

## Server-Side Rendering

All components support SSR. For Next.js App Router:

```tsx
// Server component
import { SignIn } from '@fantasticauth/react';

export default function SignInPage() {
  return <SignIn />;
}
```

For pages that need client-side interactivity, use `'use client'`:

```tsx
'use client';

import { UserButton } from '@fantasticauth/react';

export default function Header() {
  return <UserButton />;
}
```

## Accessibility

All Vault components are built with accessibility in mind:

- Full keyboard navigation support
- ARIA labels and roles
- Screen reader announcements
- Focus management
- Color contrast compliance (WCAG 2.1 AA)

Example of ARIA attributes:

```tsx
// SignIn component includes:
// - role="alert" for error messages
// - aria-label for OAuth buttons
// - aria-expanded for dropdowns
// - aria-haspopup for menu buttons
```

## TypeScript Support

All components are fully typed:

```tsx
import { SignIn, SignInProps } from '@fantasticauth/react';

// Props are fully typed
const props: SignInProps = {
  redirectUrl: '/dashboard',
  oauthProviders: ['google', 'github'],
};

<SignIn {...props} />;
```

## Error Handling

Components handle errors gracefully:

```tsx
<SignIn
  onError={(error) => {
    console.error('Sign in failed:', error.code, error.message);
    // Handle specific error codes
    if (error.code === 'invalid_credentials') {
      // Show specific error message
    }
  }}
/>
```

## Next Steps

- [SignIn Component](./sign-in.md) - Learn about the sign-in component
- [SignUp Component](./sign-up.md) - Learn about the sign-up component
- [Theming Guide](../theming/customization.md) - Customize component appearance
