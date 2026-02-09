# Migrating from Auth0

Guide for migrating your React application from Auth0 to Vault.

## Overview

Auth0 and Vault both provide authentication services, but with different approaches. This guide helps you transition from Auth0 to Vault.

## Feature Comparison

| Feature | Auth0 | Vault |
|---------|-------|-------|
| React SDK | `@auth0/auth0-react` | `@vault/react` |
| Provider | `<Auth0Provider>` | `<VaultProvider>` |
| Auth Hook | `useAuth0()` | `useAuth()` |
| Login | `loginWithRedirect()` | `signInWithOAuth()` / `signIn()` |
| Logout | `logout()` | `signOut()` |
| User | `user` | `user` |
| Loading | `isLoading` | `isLoaded` |
| Authenticated | `isAuthenticated` | `isSignedIn` |

## Installation

### Remove Auth0

```bash
npm uninstall @auth0/auth0-react
```

### Install Vault

```bash
npm install @vault/react
```

## Environment Variables

### Before (Auth0)

```bash
REACT_APP_AUTH0_DOMAIN=your-domain.auth0.com
REACT_APP_AUTH0_CLIENT_ID=your-client-id
REACT_APP_AUTH0_REDIRECT_URI=http://localhost:3000/callback
```

### After (Vault)

```bash
NEXT_PUBLIC_VAULT_API_URL=https://api.vault.dev
NEXT_PUBLIC_VAULT_TENANT_ID=your-tenant-id
```

## Provider Migration

### Before (Auth0)

```tsx
import { Auth0Provider } from '@auth0/auth0-react';

function App() {
  return (
    <Auth0Provider
      domain={process.env.REACT_APP_AUTH0_DOMAIN}
      clientId={process.env.REACT_APP_AUTH0_CLIENT_ID}
      authorizationParams={{
        redirect_uri: window.location.origin,
      }}
    >
      <YourApp />
    </Auth0Provider>
  );
}
```

### After (Vault)

```tsx
import { VaultProvider } from '@vault/react';

function App() {
  return (
    <VaultProvider
      config={{
        apiUrl: process.env.NEXT_PUBLIC_VAULT_API_URL,
        tenantId: process.env.NEXT_PUBLIC_VAULT_TENANT_ID,
      }}
    >
      <YourApp />
    </VaultProvider>
  );
}
```

## Hook Migration

### useAuth0 → useAuth

#### Before (Auth0)

```tsx
import { useAuth0 } from '@auth0/auth0-react';

function Component() {
  const { 
    isAuthenticated, 
    isLoading, 
    user, 
    loginWithRedirect, 
    logout 
  } = useAuth0();
  
  if (isLoading) return <div>Loading...</div>;
  
  return (
    <div>
      {isAuthenticated ? (
        <button onClick={() => logout()}>Log Out</button>
      ) : (
        <button onClick={loginWithRedirect}>Log In</button>
      )}
    </div>
  );
}
```

#### After (Vault)

```tsx
import { useAuth } from '@vault/react';

function Component() {
  const { 
    isSignedIn, 
    isLoaded, 
    user, 
    signInWithOAuth, 
    signOut 
  } = useAuth();
  
  if (!isLoaded) return <div>Loading...</div>;
  
  return (
    <div>
      {isSignedIn ? (
        <button onClick={signOut}>Sign Out</button>
      ) : (
        <button onClick={() => signInWithOAuth({ provider: 'google' })}>
          Sign In
        </button>
      )}
    </div>
  );
}
```

## Login Migration

### Before (Auth0)

```tsx
import { useAuth0 } from '@auth0/auth0-react';

function LoginButton() {
  const { loginWithRedirect } = useAuth0();

  return (
    <button onClick={loginWithRedirect}>
      Log In
    </button>
  );
}
```

### After (Vault)

```tsx
import { SignIn } from '@vault/react';

// Or use the component
function LoginPage() {
  return <SignIn redirectUrl="/dashboard" />;
}

// Or use the hook
import { useSignIn } from '@vault/react';

function LoginButton() {
  const { signInWithOAuth } = useSignIn();

  return (
    <button onClick={() => signInWithOAuth({ provider: 'google' })}>
      Sign In with Google
    </button>
  );
}
```

## Logout Migration

### Before (Auth0)

```tsx
import { useAuth0 } from '@auth0/auth0-react';

function LogoutButton() {
  const { logout } = useAuth0();

  return (
    <button onClick={() => logout({ returnTo: window.location.origin })}>
      Log Out
    </button>
  );
}
```

### After (Vault)

```tsx
import { useAuth } from '@vault/react';

function LogoutButton() {
  const { signOut } = useAuth();

  return (
    <button onClick={signOut}>
      Sign Out
    </button>
  );
}
```

## Protected Route Migration

### Before (Auth0)

```tsx
import { withAuthenticationRequired } from '@auth0/auth0-react';

function ProtectedComponent() {
  return <div>Protected content</div>;
}

export default withAuthenticationRequired(ProtectedComponent, {
  onRedirecting: () => <div>Loading...</div>,
});
```

### After (Vault)

```tsx
import { Protect } from '@vault/react';

function ProtectedComponent() {
  return (
    <Protect fallback={<div>Loading...</div>}>
      <div>Protected content</div>
    </Protect>
  );
}
```

## User Information

### Before (Auth0)

```tsx
import { useAuth0 } from '@auth0/auth0-react';

function Profile() {
  const { user, isAuthenticated } = useAuth0();

  if (!isAuthenticated) return <div>Not logged in</div>;

  return (
    <div>
      <img src={user.picture} alt={user.name} />
      <h2>{user.name}</h2>
      <p>{user.email}</p>
    </div>
  );
}
```

### After (Vault)

```tsx
import { useAuth, useUser } from '@vault/react';

function Profile() {
  const { isSignedIn } = useAuth();
  const user = useUser();

  if (!isSignedIn) return <div>Not signed in</div>;

  return (
    <div>
      <img src={user?.profile?.picture} alt={user?.profile?.name} />
      <h2>{user?.profile?.name}</h2>
      <p>{user?.email}</p>
    </div>
  );
}
```

## API Authorization

### Before (Auth0)

```tsx
import { useAuth0 } from '@auth0/auth0-react';

async function callApi() {
  const { getAccessTokenSilently } = useAuth0();
  
  const token = await getAccessTokenSilently({
    authorizationParams: {
      audience: 'https://api.example.com',
    },
  });
  
  const response = await fetch('/api/data', {
    headers: { Authorization: `Bearer ${token}` },
  });
}
```

### After (Vault)

```tsx
import { useSession } from '@vault/react';

async function callApi() {
  const { getToken } = useSession();
  
  const token = await getToken();
  
  const response = await fetch('/api/data', {
    headers: { Authorization: `Bearer ${token}` },
  });
}
```

## Pre-built Components

### Before (Auth0)

Auth0 doesn't provide pre-built UI components. You build your own:

```tsx
function CustomLogin() {
  const { loginWithRedirect } = useAuth0();
  
  return (
    <button onClick={loginWithRedirect}>
      Log In
    </button>
  );
}
```

### After (Vault)

Vault provides complete UI components:

```tsx
import { SignIn, SignUp, UserButton, UserProfile } from '@vault/react';

// Complete sign-in form
<SignIn redirectUrl="/dashboard" />

// Complete sign-up form
<SignUp redirectUrl="/dashboard" />

// User menu with avatar
<UserButton />

// Full profile management
<UserProfile />
```

## Differences to Note

1. **State naming** - `isLoading` → `isLoaded`, `isAuthenticated` → `isSignedIn`
2. **Pre-built UI** - Vault provides more built-in components
3. **User structure** - Auth0 user object is flatter; Vault uses `user.profile`
4. **Token retrieval** - `getAccessTokenSilently` → `getToken`
5. **OAuth flow** - Auth0 handles OAuth automatically; Vault requires explicit provider selection

## Migration Checklist

- [ ] Install `@vault/react`
- [ ] Update environment variables
- [ ] Replace `<Auth0Provider>` with `<VaultProvider>`
- [ ] Update imports from `@auth0/auth0-react` to `@vault/react`
- [ ] Update `useAuth0()` to `useAuth()`
- [ ] Rename `isLoading` to `!isLoaded`
- [ ] Rename `isAuthenticated` to `isSignedIn`
- [ ] Replace `loginWithRedirect` with `signInWithOAuth` or `<SignIn />`
- [ ] Replace `logout` with `signOut`
- [ ] Replace `getAccessTokenSilently` with `getToken`
- [ ] Update protected routes to use `<Protect />`
- [ ] Add pre-built components (`<SignIn />`, `<UserButton />`, etc.)
- [ ] Update user property access (`user.name` → `user.profile.name`)
- [ ] Test all authentication flows
- [ ] Test API calls with new token method

## Key Benefits of Vault

1. **Pre-built UI components** - Ready-to-use forms and buttons
2. **Simpler API** - Less configuration required
3. **Built-in user management** - Profile editing included
4. **Organizations** - Built-in B2B support
5. **Magic links** - Passwordless authentication built-in

## Support

For migration assistance:
- [Vault Documentation](../README.md)
- [GitHub Issues](https://github.com/vault/auth/issues)
