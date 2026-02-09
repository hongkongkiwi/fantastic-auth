# useSignIn Hook

The `useSignIn` hook provides sign-in functionality with loading states and error handling.

## Overview

The `useSignIn` hook is ideal for building custom sign-in forms with:
- Loading state management
- Error handling
- Multiple authentication methods
- Error reset capability

## Basic Usage

```tsx
import { useSignIn } from '@vault/react';
import { useState } from 'react';

function SignInForm() {
  const { signIn, isLoading, error, resetError } = useSignIn();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      await signIn({ email, password });
      // Sign-in successful - user will be authenticated
    } catch {
      // Error is available in the `error` state
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <input
        type="email"
        value={email}
        onChange={(e) => {
          setEmail(e.target.value);
          resetError();
        }}
        disabled={isLoading}
        placeholder="Email"
      />
      <input
        type="password"
        value={password}
        onChange={(e) => {
          setPassword(e.target.value);
          resetError();
        }}
        disabled={isLoading}
        placeholder="Password"
      />
      
      {error && <div role="alert">{error.message}</div>}
      
      <button type="submit" disabled={isLoading}>
        {isLoading ? 'Signing in...' : 'Sign In'}
      </button>
    </form>
  );
}
```

## Return Value

```tsx
interface UseSignInReturn {
  isLoading: boolean;
  error: ApiError | null;
  signIn: (options: SignInOptions) => Promise<void>;
  signInWithMagicLink: (options: MagicLinkOptions) => Promise<void>;
  signInWithOAuth: (options: OAuthOptions) => Promise<void>;
  resetError: () => void;
}
```

| Property | Type | Description |
|----------|------|-------------|
| `isLoading` | `boolean` | Whether a sign-in operation is in progress |
| `error` | `ApiError \| null` | Last error, if any |
| `signIn` | `(options) => Promise<void>` | Sign in with email/password |
| `signInWithMagicLink` | `(options) => Promise<void>` | Send magic link |
| `signInWithOAuth` | `(options) => Promise<void>` | Sign in with OAuth |
| `resetError` | `() => void` | Clear the error state |

## SignInOptions

```tsx
interface SignInOptions {
  email: string;
  password: string;
  turnstileToken?: string;
}
```

## Examples

### Email/Password Sign In

```tsx
import { useSignIn } from '@vault/react';
import { useState } from 'react';

function EmailSignIn() {
  const { signIn, isLoading, error, resetError } = useSignIn();
  const [formData, setFormData] = useState({ email: '', password: '' });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    resetError();

    try {
      await signIn({
        email: formData.email,
        password: formData.password,
      });
      // Success - user is now authenticated
    } catch {
      // Error is in `error` state
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <input
        type="email"
        value={formData.email}
        onChange={(e) => setFormData({ ...formData, email: e.target.value })}
        disabled={isLoading}
      />
      <input
        type="password"
        value={formData.password}
        onChange={(e) => setFormData({ ...formData, password: e.target.value })}
        disabled={isLoading}
      />
      {error && <p className="error">{error.message}</p>}
      <button type="submit" disabled={isLoading}>
        {isLoading ? 'Signing in...' : 'Sign In'}
      </button>
    </form>
  );
}
```

### OAuth Sign In

```tsx
import { useSignIn } from '@vault/react';

function OAuthButtons() {
  const { signInWithOAuth, isLoading } = useSignIn();

  const handleGoogle = () => {
    signInWithOAuth({
      provider: 'google',
      redirectUrl: '/dashboard',
    });
  };

  const handleGitHub = () => {
    signInWithOAuth({
      provider: 'github',
      redirectUrl: '/dashboard',
    });
  };

  return (
    <div>
      <button onClick={handleGoogle} disabled={isLoading}>
        Continue with Google
      </button>
      <button onClick={handleGitHub} disabled={isLoading}>
        Continue with GitHub
      </button>
    </div>
  );
}
```

### Magic Link Sign In

```tsx
import { useSignIn } from '@vault/react';
import { useState } from 'react';

function MagicLinkForm() {
  const { signInWithMagicLink, isLoading, error, resetError } = useSignIn();
  const [email, setEmail] = useState('');
  const [sent, setSent] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    resetError();

    try {
      await signInWithMagicLink({
        email,
        redirectUrl: '/dashboard',
      });
      setSent(true);
    } catch {
      // Error is in `error` state
    }
  };

  if (sent) {
    return <p>Check your email for the magic link!</p>;
  }

  return (
    <form onSubmit={handleSubmit}>
      <input
        type="email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        disabled={isLoading}
        placeholder="Enter your email"
      />
      {error && <p className="error">{error.message}</p>}
      <button type="submit" disabled={isLoading}>
        {isLoading ? 'Sending...' : 'Send Magic Link'}
      </button>
    </form>
  );
}
```

### Complete Sign In Page

```tsx
import { useSignIn } from '@vault/react';
import { useState } from 'react';

function SignInPage() {
  const {
    signIn,
    signInWithMagicLink,
    signInWithOAuth,
    isLoading,
    error,
    resetError,
  } = useSignIn();

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [useMagicLink, setUseMagicLink] = useState(false);
  const [magicLinkSent, setMagicLinkSent] = useState(false);

  const handleEmailSignIn = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (useMagicLink) {
      await signInWithMagicLink({ email, redirectUrl: '/dashboard' });
      setMagicLinkSent(true);
    } else {
      await signIn({ email, password });
    }
  };

  if (magicLinkSent) {
    return (
      <div>
        <h2>Check your email</h2>
        <p>We've sent a magic link to {email}</p>
      </div>
    );
  }

  return (
    <div className="sign-in-page">
      <form onSubmit={handleEmailSignIn}>
        <input
          type="email"
          value={email}
          onChange={(e) => { setEmail(e.target.value); resetError(); }}
          placeholder="Email"
          disabled={isLoading}
        />
        
        {!useMagicLink && (
          <input
            type="password"
            value={password}
            onChange={(e) => { setPassword(e.target.value); resetError(); }}
            placeholder="Password"
            disabled={isLoading}
          />
        )}
        
        {error && <p className="error">{error.message}</p>}
        
        <button type="submit" disabled={isLoading}>
          {isLoading
            ? 'Please wait...'
            : useMagicLink
            ? 'Send Magic Link'
            : 'Sign In'}
        </button>
        
        <button
          type="button"
          onClick={() => {
            setUseMagicLink(!useMagicLink);
            resetError();
          }}
        >
          {useMagicLink ? 'Use password' : 'Use magic link'}
        </button>
      </form>

      <div className="divider">or</div>

      <div className="oauth-buttons">
        <button
          onClick={() => signInWithOAuth({ provider: 'google' })}
          disabled={isLoading}
        >
          Continue with Google
        </button>
        <button
          onClick={() => signInWithOAuth({ provider: 'github' })}
          disabled={isLoading}
        >
          Continue with GitHub
        </button>
      </div>
    </div>
  );
}
```

## Error Handling

Common error codes and how to handle them:

```tsx
import { useSignIn } from '@vault/react';

function SignInWithErrorHandling() {
  const { signIn, error } = useSignIn();

  const getErrorMessage = () => {
    if (!error) return null;

    switch (error.code) {
      case 'invalid_credentials':
        return 'Email or password is incorrect';
      case 'user_not_found':
        return 'No account found with this email';
      case 'email_not_verified':
        return 'Please verify your email before signing in';
      case 'mfa_required':
        return 'Please complete two-factor authentication';
      case 'account_suspended':
        return 'Your account has been suspended';
      case 'rate_limit_exceeded':
        return 'Too many attempts. Please try again later';
      default:
        return error.message;
    }
  };

  return (
    <form>
      {getErrorMessage() && (
        <div role="alert" className="error">
          {getErrorMessage()}
        </div>
      )}
      {/* Form fields */}
    </form>
  );
}
```

## Error Codes

| Code | Description |
|------|-------------|
| `invalid_credentials` | Email or password is incorrect |
| `user_not_found` | No user exists with this email |
| `email_not_verified` | Email requires verification |
| `mfa_required` | Multi-factor authentication required |
| `account_suspended` | User account has been suspended |
| `account_deactivated` | User account has been deactivated |
| `rate_limit_exceeded` | Too many attempts, please wait |
| `oauth_error` | OAuth provider error |
| `network_error` | Network connection error |

## Comparison with useAuth

| Feature | useSignIn | useAuth |
|---------|-----------|---------|
| Loading state | ✅ | ❌ |
| Error state | ✅ | ❌ |
| Error reset | ✅ | ❌ |
| Best for | Custom forms | Simple operations |

## TypeScript

Full TypeScript support:

```tsx
import { useSignIn, SignInOptions, ApiError } from '@vault/react';

const handleSignIn = async (options: SignInOptions) => {
  const { signIn } = useSignIn();
  
  try {
    await signIn(options);
  } catch (err) {
    const error = err as ApiError;
    console.error(error.code, error.message);
  }
};
```

## Testing

Test the useSignIn hook:

```tsx
import { renderHook, act } from '@testing-library/react';
import { useSignIn, VaultProvider } from '@vault/react';

const wrapper = ({ children }) => (
  <VaultProvider config={{ apiUrl: 'https://test', tenantId: 'test' }}>
    {children}
  </VaultProvider>
);

test('useSignIn returns correct initial state', () => {
  const { result } = renderHook(() => useSignIn(), { wrapper });

  expect(result.current.isLoading).toBe(false);
  expect(result.current.error).toBeNull();
});

test('resetError clears error state', () => {
  const { result } = renderHook(() => useSignIn(), { wrapper });

  // Simulate an error
  // ... trigger error ...

  act(() => {
    result.current.resetError();
  });

  expect(result.current.error).toBeNull();
});
```

## Best Practices

1. **Always use `resetError`** when user modifies form fields
2. **Disable inputs** during `isLoading` state
3. **Handle MFA** separately using `authState.status === 'mfa_required'`
4. **Provide clear error messages** based on error codes
5. **Show loading states** to prevent double submissions

## See Also

- [useAuth Hook](./use-auth.md) - General authentication
- [useSignUp Hook](./use-sign-up.md) - Registration
- [SignIn Component](../components/sign-in.md) - Pre-built sign-in form
