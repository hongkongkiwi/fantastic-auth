# SignUp Component

The `SignUp` component provides a complete, ready-to-use registration form with support for email/password and OAuth sign-up.

## Overview

The SignUp component handles:
- Email/password registration
- OAuth sign-up (Google, GitHub, Microsoft)
- Name collection
- Password validation
- Terms acceptance
- Error handling and validation

## Basic Usage

```tsx
import { SignUp } from '@fantasticauth/react';

function SignUpPage() {
  return <SignUp />;
}
```

## Props

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `redirectUrl` | `string` | - | URL to redirect after successful sign up |
| `onSignUp` | `() => void` | - | Callback fired after successful sign up |
| `onError` | `(error: ApiError) => void` | - | Callback fired on sign up error |
| `oauthProviders` | `Array<'google' \| 'github' \| 'microsoft'>` | `[]` | Enabled OAuth providers |
| `requireName` | `boolean` | `false` | Require name field |
| `appearance` | `Appearance` | - | Custom styling configuration |
| `className` | `string` | - | Additional CSS class names |

## Examples

### Basic Sign Up

```tsx
<SignUp redirectUrl="/onboarding" />
```

### With OAuth

```tsx
<SignUp
  redirectUrl="/onboarding"
  oauthProviders={['google', 'github']}
/>
```

### With Name Collection

```tsx
<SignUp
  redirectUrl="/onboarding"
  requireName={true}
/>
```

### With Custom Styling

```tsx
<SignUp
  redirectUrl="/onboarding"
  oauthProviders={['google']}
  requireName={true}
  appearance={{
    theme: 'light',
    variables: {
      colorPrimary: '#10b981',
      borderRadius: '12px',
    },
  }}
/>
```

### With Event Handlers

```tsx
<SignUp
  redirectUrl="/onboarding"
  onSignUp={() => {
    console.log('Account created!');
    analytics.track('Sign Up Success');
    // Initialize user profile
  }}
  onError={(error) => {
    console.error('Sign up failed:', error);
    analytics.track('Sign Up Error', { code: error.code });
  }}
/>
```

### Complete Configuration

```tsx
<SignUp
  redirectUrl="/onboarding"
  onSignUp={() => console.log('Signed up!')}
  onError={(error) => console.error(error)}
  oauthProviders={['google', 'github', 'microsoft']}
  requireName={true}
  appearance={{
    theme: 'light',
    variables: {
      colorPrimary: '#10b981',
      colorDanger: '#ef4444',
      borderRadius: '8px',
      fontSize: '16px',
    },
  }}
  className="my-sign-up"
/>
```

## Password Validation

The SignUp component enforces password requirements:

- **Minimum length**: 12 characters
- **Confirmation**: Passwords must match
- **Visual feedback**: Password strength indicators

```tsx
<SignUp
  redirectUrl="/onboarding"
  // Password requirements are enforced automatically
/>
```

Custom password requirements (configure in Vault dashboard):
- Require uppercase letters
- Require lowercase letters
- Require numbers
- Require special characters
- Minimum length

## OAuth Sign Up

Users can sign up with their existing accounts:

```tsx
<SignUp
  redirectUrl="/onboarding"
  oauthProviders={['google', 'github']}
/>
```

OAuth flow:
1. User clicks OAuth provider button
2. Redirected to provider's authorization page
3. User authorizes the application
4. Redirected back to your app
5. Account created automatically
6. User redirected to `redirectUrl`

## Name Collection

Collect the user's name during registration:

```tsx
<SignUp
  redirectUrl="/onboarding"
  requireName={true}
/>
```

When `requireName` is `true`:
- Name field is displayed
- Name field is required
- Validation error shown if empty

When `requireName` is `false`:
- Name field is optional
- Shown as a collapsible field

## Error Handling

Handle sign-up errors gracefully:

```tsx
<SignUp
  onError={(error) => {
    switch (error.code) {
      case 'email_already_exists':
        // Handle duplicate email
        break;
      case 'weak_password':
        // Handle weak password
        break;
      case 'invalid_email':
        // Handle invalid email format
        break;
      case 'rate_limit_exceeded':
        // Handle rate limiting
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
| `email_already_exists` | An account with this email already exists |
| `weak_password` | Password doesn't meet requirements |
| `invalid_email` | Email format is invalid |
| `rate_limit_exceeded` | Too many attempts, please wait |
| `oauth_error` | OAuth provider error |
| `tenant_not_found` | Invalid tenant configuration |

## Customization

### CSS Classes

Apply custom classes:

```tsx
<SignUp className="custom-sign-up" />
```

Then style with CSS:

```css
.custom-sign-up {
  max-width: 450px;
  margin: 2rem auto;
}
```

### Appearance Variables

Customize the look and feel:

```tsx
<SignUp
  appearance={{
    theme: 'light',
    variables: {
      colorPrimary: '#10b981',
      colorDanger: '#ef4444',
      borderRadius: '8px',
      fontSize: '16px',
    },
  }}
/>
```

### Element Overrides

Style individual elements:

```tsx
<SignUp
  appearance={{
    elements: {
      button: {
        backgroundColor: '#10b981',
        padding: '14px 28px',
      },
      input: {
        borderWidth: '2px',
      },
      title: {
        fontSize: '28px',
      },
    },
  }}
/>
```

See the [Theming Guide](../theming/customization.md) for complete styling options.

## Success State

After successful sign-up:

1. Account is created
2. User is automatically signed in
3. `onSignUp` callback is fired
4. User is redirected to `redirectUrl` (if provided)
5. Success message is displayed briefly

```tsx
<SignUp
  redirectUrl="/welcome"
  onSignUp={() => {
    // User is now signed in
    // Redirect happens automatically
  }}
/>
```

## Email Verification

If email verification is required:

1. Account is created
2. Verification email is sent
3. User sees verification prompt
4. User must verify email before full access

Configure email verification in your Vault dashboard.

## Server-Side Rendering

The SignUp component works with SSR:

```tsx
// Next.js App Router - Server Component
import { SignUp } from '@fantasticauth/react';

export default function SignUpPage() {
  return <SignUp redirectUrl="/onboarding" />;
}
```

## TypeScript

Full TypeScript support:

```tsx
import { SignUp, SignUpProps, ApiError } from '@fantasticauth/react';

const handleError = (error: ApiError) => {
  console.error(error.code, error.message);
};

const props: SignUpProps = {
  redirectUrl: '/onboarding',
  requireName: true,
  onError: handleError,
};

<SignUp {...props} />;
```

## Integration with Onboarding

Common pattern for post-sign-up onboarding:

```tsx
import { SignUp, useAuth } from '@fantasticauth/react';
import { useEffect } from 'react';
import { useRouter } from 'next/router';

function OnboardingFlow() {
  const { user, isSignedIn } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (isSignedIn && user) {
      // Check if onboarding is complete
      if (!user.profile?.onboardingComplete) {
        router.push('/onboarding');
      } else {
        router.push('/dashboard');
      }
    }
  }, [isSignedIn, user]);

  return (
    <SignUp
      redirectUrl="/onboarding"
      requireName={true}
    />
  );
}
```

## Testing

Test the SignUp component:

```tsx
import { render, screen, fireEvent } from '@testing-library/react';
import { SignUp } from '@fantasticauth/react';
import { VaultProvider } from '@fantasticauth/react';

const wrapper = ({ children }: { children: React.ReactNode }) => (
  <VaultProvider config={{ apiUrl: 'https://test', tenantId: 'test' }}>
    {children}
  </VaultProvider>
);

test('renders sign up form', () => {
  render(<SignUp />, { wrapper });
  
  expect(screen.getByLabelText(/email/i)).toBeInTheDocument();
  expect(screen.getByLabelText(/^password/i)).toBeInTheDocument();
  expect(screen.getByLabelText(/confirm password/i)).toBeInTheDocument();
});

test('shows name field when required', () => {
  render(<SignUp requireName={true} />, { wrapper });
  
  expect(screen.getByLabelText(/full name/i)).toBeInTheDocument();
});

test('validates password confirmation', async () => {
  render(<SignUp />, { wrapper });
  
  fireEvent.change(screen.getByLabelText(/^password/i), {
    target: { value: 'password123' },
  });
  fireEvent.change(screen.getByLabelText(/confirm password/i), {
    target: { value: 'different' },
  });
  fireEvent.click(screen.getByRole('button', { name: /create account/i }));
  
  expect(await screen.findByText(/passwords do not match/i)).toBeInTheDocument();
});
```

## Accessibility

The SignUp component includes:

- Semantic HTML structure
- ARIA labels for all inputs
- Error announcements via `role="alert"`
- Keyboard navigation support
- Password visibility toggle (optional)
- High contrast mode support

```tsx
// ARIA attributes included:
// - aria-required on required fields
// - aria-invalid on invalid inputs
// - aria-describedby linking hints/errors to inputs
// - role="alert" on error messages
```

## See Also

- [SignIn Component](./sign-in.md) - User authentication
- [UserProfile Component](./user-profile.md) - Profile management
- [Theming Guide](../theming/customization.md) - Customize appearance
