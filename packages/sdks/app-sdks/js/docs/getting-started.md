# Getting Started

Get up and running with the Vault React SDK in 5 minutes.

## Prerequisites

Before you begin, you'll need:

1. A Vault account - [Sign up here](https://vault.dev/signup)
2. A tenant ID from your Vault dashboard
3. A React project (Create React App, Next.js, Vite, etc.)

## Step 1: Install the SDK

```bash
npm install @fantasticauth/react
```

## Step 2: Configure Environment Variables

Create a `.env` file in your project root:

```bash
# For Next.js
NEXT_PUBLIC_VAULT_API_URL=https://api.vault.dev
NEXT_PUBLIC_VAULT_TENANT_ID=your-tenant-id

# For other frameworks
VAULT_API_URL=https://api.vault.dev
VAULT_TENANT_ID=your-tenant-id
```

## Step 3: Wrap Your App with VaultProvider

```tsx
// App.tsx or app/layout.tsx
import { VaultProvider } from '@fantasticauth/react';

function App() {
  return (
    <VaultProvider
      config={{
        apiUrl: process.env.VAULT_API_URL || 'https://api.vault.dev',
        tenantId: process.env.VAULT_TENANT_ID || 'your-tenant-id',
      }}
    >
      <YourApp />
    </VaultProvider>
  );
}
```

## Step 4: Add Authentication to Your App

### Using Pre-built Components

The simplest way to add authentication:

```tsx
import { useAuth, SignIn, UserButton } from '@fantasticauth/react';

function Header() {
  const { isSignedIn } = useAuth();

  return (
    <header>
      {isSignedIn ? <UserButton /> : <a href="/sign-in">Sign In</a>}
    </header>
  );
}

function SignInPage() {
  return (
    <SignIn
      redirectUrl="/dashboard"
      oauthProviders={['google', 'github']}
    />
  );
}
```

### Using Hooks for Custom UI

For complete control over the UI:

```tsx
import { useSignIn } from '@fantasticauth/react';

function CustomSignIn() {
  const { signIn, isLoading, error } = useSignIn();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await signIn({ email, password });
    } catch (err) {
      // Error is handled by the error state
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <input
        type="email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        placeholder="Email"
      />
      <input
        type="password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        placeholder="Password"
      />
      {error && <p className="error">{error.message}</p>}
      <button type="submit" disabled={isLoading}>
        {isLoading ? 'Signing in...' : 'Sign In'}
      </button>
    </form>
  );
}
```

## Step 5: Protect Routes

Use the `Protect` component to secure pages:

```tsx
import { Protect } from '@fantasticauth/react';

function Dashboard() {
  return (
    <Protect>
      <div>
        <h1>Dashboard</h1>
        <p>This content is only visible to signed-in users.</p>
      </div>
    </Protect>
  );
}
```

Or with role-based access:

```tsx
import { Protect } from '@fantasticauth/react';

function AdminPanel() {
  return (
    <Protect role="admin">
      <div>
        <h1>Admin Panel</h1>
        <p>Only admins can see this.</p>
      </div>
    </Protect>
  );
}
```

## Step 6: Access User Data

Use the `useAuth` hook to access user information:

```tsx
import { useAuth } from '@fantasticauth/react';

function Profile() {
  const { user, isSignedIn, signOut } = useAuth();

  if (!isSignedIn) {
    return <p>Please sign in</p>;
  }

  return (
    <div>
      <h1>Welcome, {user?.profile?.name || user?.email}</h1>
      <button onClick={signOut}>Sign Out</button>
    </div>
  );
}
```

## Common Patterns

### Conditional Rendering

```tsx
import { SignedIn, SignedOut } from '@fantasticauth/react';

function Header() {
  return (
    <nav>
      <SignedIn>
        <UserButton />
      </SignedIn>
      <SignedOut>
        <a href="/sign-in">Sign In</a>
        <a href="/sign-up">Sign Up</a>
      </SignedOut>
    </nav>
  );
}
```

### Loading States

```tsx
import { useAuth } from '@fantasticauth/react';

function App() {
  const { isLoaded, isSignedIn } = useAuth();

  if (!isLoaded) {
    return <div>Loading...</div>;
  }

  return (
    <div>
      {isSignedIn ? <Dashboard /> : <LandingPage />}
    </div>
  );
}
```

### Handle Auth State Changes

```tsx
import { useEffect } from 'react';
import { useAuth } from '@fantasticauth/react';

function App() {
  const { user, isSignedIn } = useAuth();

  useEffect(() => {
    if (isSignedIn && user) {
      // User just signed in
      console.log('User signed in:', user.email);
      
      // Track sign-in event
      analytics.track('Signed In', { userId: user.id });
    }
  }, [isSignedIn, user]);

  return <div>{/* Your app content */}</div>;
}
```

## First Login Flow

1. Navigate to your sign-in page
2. Enter credentials or use OAuth
3. On success, user is redirected to your `redirectUrl`
4. The `useAuth` hook now returns `isSignedIn: true`
5. User data is available via `user` object

## Common Pitfalls

### 1. Provider Not Found

**Error**: `useVault must be used within a VaultProvider`

**Solution**: Ensure `VaultProvider` wraps your entire app, typically in your root component.

### 2. Environment Variables Not Loading

**Error**: `tenantId is required`

**Solution**: 
- Check that environment variables are prefixed correctly (e.g., `NEXT_PUBLIC_` for Next.js)
- Restart your dev server after creating `.env` file
- Verify the variable names match exactly

### 3. Hydration Mismatch (Next.js)

**Error**: React hydration mismatch

**Solution**: Use the `useEffect` pattern for client-side only rendering, or use the `initialUser` prop for SSR.

### 4. OAuth Redirect Issues

**Issue**: OAuth flow doesn't redirect correctly

**Solution**: Ensure your redirect URL is configured in the Vault dashboard and matches exactly.

## Next Steps

- [Configuration](./configuration.md) - Learn all configuration options
- [SignIn Component](./components/sign-in.md) - Customize the sign-in experience
- [useAuth Hook](./hooks/use-auth.md) - Master the primary auth hook
- [Next.js Example](./examples/nextjs-app-router.md) - Full Next.js setup

## Example: Complete App

```tsx
// App.tsx
import { VaultProvider, useAuth, SignIn, UserButton } from '@fantasticauth/react';

function App() {
  return (
    <VaultProvider
      config={{
        apiUrl: 'https://api.vault.dev',
        tenantId: 'your-tenant-id',
      }}
    >
      <Main />
    </VaultProvider>
  );
}

function Main() {
  const { isLoaded, isSignedIn, user } = useAuth();

  if (!isLoaded) {
    return <div>Loading...</div>;
  }

  return (
    <div>
      <header style={{ padding: '1rem', borderBottom: '1px solid #eee' }}>
        {isSignedIn ? (
          <UserButton />
        ) : (
          <nav>
            <a href="/sign-in">Sign In</a>
          </nav>
        )}
      </header>
      
      <main style={{ padding: '2rem' }}>
        {isSignedIn ? (
          <div>
            <h1>Welcome, {user?.profile?.name || user?.email}!</h1>
            <p>You are now signed in.</p>
          </div>
        ) : (
          <SignIn redirectUrl="/" />
        )}
      </main>
    </div>
  );
}

export default App;
```
