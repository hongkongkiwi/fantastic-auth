# SignIn Component

The `SignIn` component provides a complete, ready-to-use sign-in form with support for multiple authentication methods.

## Overview

The SignIn component handles:
- Email/password authentication
- Magic link authentication
- OAuth providers (Google, GitHub, Microsoft)
- WebAuthn/Passkey authentication
- Forgot password flow
- Error handling and validation

## Basic Usage

```tsx
import { SignIn } from '@vault/react';

function SignInPage() {
  return <SignIn />;
}
```

## Props

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `redirectUrl` | `string` | - | URL to redirect after successful sign in |
| `onSignIn` | `() => void` | - | Callback fired after successful sign in |
| `onError` | `(error: ApiError) => void` | - | Callback fired on sign in error |
| `showMagicLink` | `boolean` | `true` | Show magic link option |
| `showForgotPassword` | `boolean` | `true` | Show forgot password link |
| `oauthProviders` | `Array<'google' \| 'github' \| 'microsoft'>` | `[]` | Enabled OAuth providers |
| `showWebAuthn` | `boolean` | `false` | Show WebAuthn/passkey option |
| `appearance` | `Appearance` | - | Custom styling configuration |
| `className` | `string` | - | Additional CSS class names |

## Examples

### Basic Sign In

```tsx
<SignIn redirectUrl="/dashboard" />
```

### With OAuth

```tsx
<SignIn
  redirectUrl="/dashboard"
  oauthProviders={['google', 'github', 'microsoft']}
/>
```

### With Magic Link

```tsx
<SignIn
  redirectUrl="/dashboard"
  showMagicLink={true}
/>
```

### With Passkeys

```tsx
<SignIn
  redirectUrl="/dashboard"
  showWebAuthn={true}
/>
```

### With Custom Styling

```tsx
<SignIn
  redirectUrl="/dashboard"
  oauthProviders={['google', 'github']}
  appearance={{
    theme: 'light',
    variables: {
      colorPrimary: '#6366f1',
      borderRadius: '12px',
    },
  }}
/>
```

### With Event Handlers

```tsx
<SignIn
  redirectUrl="/dashboard"
  onSignIn={() => {
    console.log('User signed in!');
    analytics.track('Sign In Success');
  }}
  onError={(error) => {
    console.error('Sign in failed:', error);
    analytics.track('Sign In Error', { code: error.code });
  }}
/>
```

### Complete Configuration

```tsx
<SignIn
  redirectUrl="/dashboard"
  onSignIn={() => console.log('Signed in!')}
  onError={(error) => console.error(error)}
  showMagicLink={true}
  showForgotPassword={true}
  oauthProviders={['google', 'github', 'microsoft']}
  showWebAuthn={true}
  appearance={{
    theme: 'light',
    variables: {
      colorPrimary: '#6366f1',
      colorDanger: '#ef4444',
      borderRadius: '8px',
      fontSize: '16px',
    },
  }}
  className="my-sign-in"
/>
```

## OAuth Configuration

Before using OAuth providers, configure them in your Vault dashboard:

### Google

```tsx
<SignIn oauthProviders={['google']} />
```

### GitHub

```tsx
<SignIn oauthProviders={['github']} />
```

### Microsoft

```tsx
<SignIn oauthProviders={['microsoft']} />
```

### Multiple Providers

```tsx
<SignIn
  oauthProviders={['google', 'github', 'microsoft']}
/>
```

## WebAuthn/Passkey Setup

Enable passkey authentication:

```tsx
<SignIn
  showWebAuthn={true}
  redirectUrl="/dashboard"
/>
```

The component will:
1. Check if the browser supports WebAuthn
2. Show a "Sign in with Passkey" button if supported
3. Handle the authentication flow automatically

## Magic Link Flow

When `showMagicLink` is enabled:

1. User enters their email
2. User clicks "Use magic link instead"
3. Component switches to magic link mode
4. User clicks "Send Magic Link"
5. Success message is shown
6. User receives email with sign-in link

```tsx
<SignIn
  showMagicLink={true}
  redirectUrl="/dashboard"
/>
```

## Error Handling

The component handles various error scenarios:

```tsx
<SignIn
  onError={(error) => {
    switch (error.code) {
      case 'invalid_credentials':
        // Handle invalid email/password
        break;
      case 'user_not_found':
        // Handle non-existent user
        break;
      case 'email_not_verified':
        // Handle unverified email
        break;
      case 'mfa_required':
        // Handle MFA requirement
        break;
      default:
        // Handle generic error
    }
  }}
/>
```

Common error codes:

| Code | Description |
|------|-------------|
| `invalid_credentials` | Email or password is incorrect |
| `user_not_found` | No user exists with this email |
| `email_not_verified` | Email requires verification |
| `mfa_required` | Multi-factor authentication required |
| `rate_limit_exceeded` | Too many attempts, please wait |
| `account_suspended` | User account has been suspended |

## Customization

### CSS Classes

Apply custom classes:

```tsx
<SignIn className="custom-sign-in" />
```

Then style with CSS:

```css
.custom-sign-in {
  max-width: 450px;
  margin: 2rem auto;
}
```

### Appearance Variables

Customize the look and feel:

```tsx
<SignIn
  appearance={{
    theme: 'light',
    variables: {
      // Colors
      colorPrimary: '#6366f1',
      colorDanger: '#ef4444',
      colorSuccess: '#10b981',
      
      // Typography
      fontSize: '16px',
      fontFamily: 'Inter, sans-serif',
      
      // Spacing
      borderRadius: '8px',
      spacingUnit: '1rem',
    },
  }}
/>
```

### Element Overrides

Style individual elements:

```tsx
<SignIn
  appearance={{
    elements: {
      button: {
        padding: '14px 28px',
        fontWeight: 600,
      },
      input: {
        borderWidth: '2px',
        borderColor: '#e5e7eb',
      },
      error: {
        backgroundColor: '#fef2f2',
        borderLeft: '4px solid #ef4444',
      },
    },
  }}
/>
```

See the [Theming Guide](../theming/customization.md) for complete styling options.

## Integration with MFA

When MFA is required, the sign-in flow returns an `mfa_required` state:

```tsx
import { SignIn, MFAForm, useAuth } from '@vault/react';

function SignInPage() {
  const { authState } = useAuth();

  // Check if MFA is required
  if (authState.status === 'mfa_required') {
    return (
      <MFAForm
        onVerify={() => {
          window.location.href = '/dashboard';
        }}
      />
    );
  }

  return (
    <SignIn
      redirectUrl="/dashboard"
      onSignIn={() => console.log('Signed in without MFA')}
    />
  );
}
```

## Forgot Password Flow

The forgot password link navigates to `/forgot-password` by default:

```tsx
<SignIn
  showForgotPassword={true}
  // Links to /forgot-password?email=user@example.com
/>
```

To customize the forgot password behavior, you can:

1. Create a custom forgot password page
2. Handle the navigation manually

```tsx
// Custom sign-in without built-in forgot password
<SignIn showForgotPassword={false} />

// Add your own forgot password link
<a href="/custom-forgot-password">Forgot password?</a>
```

## Server-Side Rendering

The SignIn component works with SSR:

```tsx
// Next.js App Router - Server Component
import { SignIn } from '@vault/react';

export default function SignInPage() {
  return <SignIn redirectUrl="/dashboard" />;
}
```

## TypeScript

Full TypeScript support:

```tsx
import { SignIn, SignInProps, ApiError } from '@vault/react';

const handleError = (error: ApiError) => {
  console.error(error.code, error.message);
};

const props: SignInProps = {
  redirectUrl: '/dashboard',
  onError: handleError,
};

<SignIn {...props} />;
```

## Testing

Test the SignIn component with React Testing Library:

```tsx
import { render, screen, fireEvent } from '@testing-library/react';
import { SignIn } from '@vault/react';
import { VaultProvider } from '@vault/react';

const wrapper = ({ children }: { children: React.ReactNode }) => (
  <VaultProvider config={{ apiUrl: 'https://test', tenantId: 'test' }}>
    {children}
  </VaultProvider>
);

test('renders sign in form', () => {
  render(<SignIn />, { wrapper });
  
  expect(screen.getByLabelText(/email/i)).toBeInTheDocument();
  expect(screen.getByLabelText(/password/i)).toBeInTheDocument();
  expect(screen.getByRole('button', { name: /sign in/i })).toBeInTheDocument();
});

test('submits form with credentials', async () => {
  render(<SignIn />, { wrapper });
  
  fireEvent.change(screen.getByLabelText(/email/i), {
    target: { value: 'test@example.com' },
  });
  fireEvent.change(screen.getByLabelText(/password/i), {
    target: { value: 'password123' },
  });
  fireEvent.click(screen.getByRole('button', { name: /sign in/i }));
  
  // Assert expected behavior
});
```

## Accessibility

The SignIn component includes:

- Semantic HTML structure
- ARIA labels for all inputs
- Error announcements via `role="alert"`
- Keyboard navigation support
- Focus management
- High contrast mode support

```tsx
// ARIA attributes included:
// - aria-label on OAuth buttons
// - aria-invalid on invalid inputs
// - aria-describedby linking errors to inputs
// - role="alert" on error messages
```

## See Also

- [SignUp Component](./sign-up.md) - User registration
- [MFAForm Component](./mfa-form.md) - Multi-factor authentication
- [WebAuthnButton Component](./webauthn-button.md) - Passkey authentication
- [Theming Guide](../theming/customization.md) - Customize appearance
