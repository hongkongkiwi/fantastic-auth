# useAuth Hook

The `useAuth` hook is the primary hook for accessing authentication state and performing auth actions.

## Overview

The `useAuth` hook provides:
- Authentication state (`isSignedIn`, `isLoaded`)
- User and session data
- Sign-in and sign-up methods
- Sign-out functionality
- Organization context

## Basic Usage

```tsx
import { useAuth } from '@fantasticauth/react';

function App() {
  const { isSignedIn, user, signOut } = useAuth();

  if (!isSignedIn) {
    return <a href="/sign-in">Sign In</a>;
  }

  return (
    <div>
      <p>Welcome, {user?.email}</p>
      <button onClick={signOut}>Sign Out</button>
    </div>
  );
}
```

## Return Value

```tsx
interface UseAuthReturn {
  // State
  isLoaded: boolean;
  isSignedIn: boolean;
  user: User | null;
  session: Session | null;
  organization: Organization | null;

  // Actions
  signIn: (options: SignInOptions) => Promise<void>;
  signInWithMagicLink: (options: MagicLinkOptions) => Promise<void>;
  signInWithOAuth: (options: OAuthOptions) => Promise<void>;
  signUp: (options: SignUpOptions) => Promise<void>;
  signOut: () => Promise<void>;
}
```

### State Properties

| Property | Type | Description |
|----------|------|-------------|
| `isLoaded` | `boolean` | Whether auth state has been initialized |
| `isSignedIn` | `boolean` | Whether user is currently signed in |
| `user` | `User \| null` | Current user data |
| `session` | `Session \| null` | Current session data |
| `organization` | `Organization \| null` | Active organization (B2B) |

### Action Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `signIn` | `(options: SignInOptions) => Promise<void>` | Sign in with email/password |
| `signInWithMagicLink` | `(options: MagicLinkOptions) => Promise<void>` | Send magic link email |
| `signInWithOAuth` | `(options: OAuthOptions) => Promise<void>` | Sign in with OAuth provider |
| `signUp` | `(options: SignUpOptions) => Promise<void>` | Create new account |
| `signOut` | `() => Promise<void>` | Sign out current user |

## Examples

### Check Authentication State

```tsx
import { useAuth } from '@fantasticauth/react';

function Dashboard() {
  const { isLoaded, isSignedIn } = useAuth();

  if (!isLoaded) {
    return <div>Loading...</div>;
  }

  if (!isSignedIn) {
    return <a href="/sign-in">Please sign in</a>;
  }

  return <div>Dashboard content</div>;
}
```

### Display User Information

```tsx
import { useAuth } from '@fantasticauth/react';

function UserGreeting() {
  const { user } = useAuth();

  return (
    <div>
      <h1>Welcome, {user?.profile?.name || user?.email}</h1>
      {user?.emailVerified ? (
        <span>✓ Verified</span>
      ) : (
        <span>Please verify your email</span>
      )}
    </div>
  );
}
```

### Sign Out

```tsx
import { useAuth } from '@fantasticauth/react';
import { useRouter } from 'next/router';

function SignOutButton() {
  const { signOut } = useAuth();
  const router = useRouter();

  const handleSignOut = async () => {
    await signOut();
    router.push('/');
  };

  return <button onClick={handleSignOut}>Sign Out</button>;
}
```

### Programmatic Sign In

```tsx
import { useAuth } from '@fantasticauth/react';
import { useState } from 'react';

function SignInForm() {
  const { signIn } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      await signIn({ email, password });
      // Sign-in successful
    } catch (error) {
      // Handle error
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <input
        type="email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
      />
      <input
        type="password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
      />
      <button type="submit">Sign In</button>
    </form>
  );
}
```

### OAuth Sign In

```tsx
import { useAuth } from '@fantasticauth/react';

function OAuthButtons() {
  const { signInWithOAuth } = useAuth();

  const handleGoogleSignIn = () => {
    signInWithOAuth({ provider: 'google', redirectUrl: '/dashboard' });
  };

  const handleGitHubSignIn = () => {
    signInWithOAuth({ provider: 'github', redirectUrl: '/dashboard' });
  };

  return (
    <div>
      <button onClick={handleGoogleSignIn}>Sign in with Google</button>
      <button onClick={handleGitHubSignIn}>Sign in with GitHub</button>
    </div>
  );
}
```

### Magic Link Sign In

```tsx
import { useAuth } from '@fantasticauth/react';
import { useState } from 'react';

function MagicLinkForm() {
  const { signInWithMagicLink } = useAuth();
  const [email, setEmail] = useState('');
  const [sent, setSent] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    await signInWithMagicLink({
      email,
      redirectUrl: '/dashboard',
    });
    
    setSent(true);
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
        placeholder="Enter your email"
      />
      <button type="submit">Send Magic Link</button>
    </form>
  );
}
```

### Monitor Auth State Changes

```tsx
import { useAuth } from '@fantasticauth/react';
import { useEffect } from 'react';

function App() {
  const { isSignedIn, user } = useAuth();

  useEffect(() => {
    if (isSignedIn && user) {
      // User just signed in
      console.log('User signed in:', user.email);
      
      // Initialize user-specific features
      initializeUserFeatures(user);
      
      // Track sign-in
      analytics.track('User Signed In', {
        userId: user.id,
        email: user.email,
      });
    }
  }, [isSignedIn, user]);

  return <div>App content</div>;
}
```

## Related Hooks

### useAuthState

Lightweight hook for simple auth checks:

```tsx
import { useAuthState } from '@fantasticauth/react';

function Header() {
  const { isLoaded, isSignedIn } = useAuthState();

  if (!isLoaded) return null;

  return (
    <header>
      {isSignedIn ? <UserNav /> : <SignInLink />}
    </header>
  );
}
```

### useHasRole

Check if user has a specific role:

```tsx
import { useHasRole } from '@fantasticauth/react';

function AdminOnly() {
  const isAdmin = useHasRole('admin');

  if (!isAdmin) {
    return <p>Admin access required</p>;
  }

  return <div>Admin content</div>;
}
```

### useRequireAuth

Require authentication or throw:

```tsx
import { useRequireAuth } from '@fantasticauth/react';

function ProtectedComponent() {
  const { user, session } = useRequireAuth();

  // If not signed in, an error is thrown
  // Otherwise, user and session are guaranteed to exist

  return <div>Protected content for {user.email}</div>;
}
```

## Types

```tsx
interface User {
  id: string;
  tenantId: string;
  email: string;
  emailVerified: boolean;
  status: 'pending' | 'active' | 'suspended' | 'deactivated';
  profile: UserProfile;
  mfaEnabled: boolean;
  mfaMethods: MfaMethod[];
  lastLoginAt?: string;
  createdAt: string;
  updatedAt: string;
}

interface UserProfile {
  name?: string;
  givenName?: string;
  familyName?: string;
  picture?: string;
  phoneNumber?: string;
  [key: string]: any;
}

interface Session {
  id: string;
  accessToken: string;
  refreshToken: string;
  expiresAt: string;
  user: User;
}

interface Organization {
  id: string;
  tenantId: string;
  name: string;
  slug: string;
  logoUrl?: string;
  description?: string;
  role: 'owner' | 'admin' | 'member' | 'guest';
  createdAt: string;
  updatedAt: string;
}

interface SignInOptions {
  email: string;
  password: string;
  turnstileToken?: string;
}

interface MagicLinkOptions {
  email: string;
  redirectUrl?: string;
  turnstileToken?: string;
}

interface OAuthOptions {
  provider: 'google' | 'github' | 'microsoft' | string;
  redirectUrl?: string;
}

interface SignUpOptions {
  email: string;
  password: string;
  name?: string;
  givenName?: string;
  familyName?: string;
  turnstileToken?: string;
}
```

## Error Handling

Handle errors from auth methods:

```tsx
import { useAuth } from '@fantasticauth/react';
import { useState } from 'react';

function SignInForm() {
  const { signIn } = useAuth();
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    try {
      await signIn({ email, password });
    } catch (err: any) {
      setError(err.message);
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      {error && <div role="alert">{error}</div>}
      {/* Form fields */}
    </form>
  );
}
```

## Testing

Test components using `useAuth`:

```tsx
import { renderHook } from '@testing-library/react';
import { useAuth, VaultProvider } from '@fantasticauth/react';

const wrapper = ({ children }) => (
  <VaultProvider config={{ apiUrl: 'https://test', tenantId: 'test' }}>
    {children}
  </VaultProvider>
);

test('useAuth returns correct initial state', () => {
  const { result } = renderHook(() => useAuth(), { wrapper });

  expect(result.current.isLoaded).toBe(false);
  expect(result.current.isSignedIn).toBe(false);
  expect(result.current.user).toBeNull();
});
```

## Best Practices

1. **Always check `isLoaded`** before rendering auth-dependent UI
2. **Handle errors** from auth methods appropriately
3. **Use specific hooks** like `useUser()` when you only need user data
4. **Memoize callbacks** to prevent unnecessary re-renders

## See Also

- [useUser Hook](./use-user.md) - Get user data
- [useSession Hook](./use-session.md) - Session management
- [useSignIn Hook](./use-sign-in.md) - Sign-in with loading states
- [SignIn Component](../components/sign-in.md) - Pre-built sign-in form
