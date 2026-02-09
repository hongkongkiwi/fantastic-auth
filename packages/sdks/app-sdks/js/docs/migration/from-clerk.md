# Migrating from Clerk

Guide for migrating your React application from Clerk to Vault.

## Overview

Both Clerk and Vault provide similar authentication features. This guide helps you map Clerk concepts to Vault equivalents.

## Feature Comparison

| Feature | Clerk | Vault |
|---------|-------|-------|
| React SDK | `@clerk/clerk-react` | `@fantasticauth/react` |
| Provider | `<ClerkProvider>` | `<VaultProvider>` |
| Auth Hook | `useAuth()` | `useAuth()` |
| User Hook | `useUser()` | `useUser()` |
| Sign In | `<SignIn />` | `<SignIn />` |
| Sign Up | `<SignUp />` | `<SignUp />` |
| User Button | `<UserButton />` | `<UserButton />` |
| User Profile | `<UserProfile />` | `<UserProfile />` |
| Organization | `<OrganizationSwitcher />` | `<OrganizationSwitcher />` |
| Protected | `<SignedIn>` / `<SignedOut>` | `<SignedIn>` / `<SignedOut>` |
| Middleware | `authMiddleware()` | Custom middleware |

## Installation

### Remove Clerk

```bash
npm uninstall @clerk/clerk-react
```

### Install Vault

```bash
npm install @fantasticauth/react
```

## Environment Variables

### Before (Clerk)

```bash
REACT_APP_CLERK_PUBLISHABLE_KEY=pk_clerk_xxx...
CLERK_SECRET_KEY=sk_clerk_xxx...
```

### After (Vault)

```bash
NEXT_PUBLIC_VAULT_API_URL=https://api.vault.dev
NEXT_PUBLIC_VAULT_TENANT_ID=your-tenant-id
```

## Provider Migration

### Before (Clerk)

```tsx
import { ClerkProvider } from '@clerk/clerk-react';

function App() {
  return (
    <ClerkProvider publishableKey={process.env.REACT_APP_CLERK_PUBLISHABLE_KEY}>
      <YourApp />
    </ClerkProvider>
  );
}
```

### After (Vault)

```tsx
import { VaultProvider } from '@fantasticauth/react';

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

### useAuth

#### Before (Clerk)

```tsx
import { useAuth } from '@clerk/clerk-react';

function Component() {
  const { isSignedIn, userId, sessionId, signOut } = useAuth();
  
  return <div>{isSignedIn ? 'Signed In' : 'Signed Out'}</div>;
}
```

#### After (Vault)

```tsx
import { useAuth } from '@fantasticauth/react';

function Component() {
  const { isSignedIn, user, session, signOut } = useAuth();
  
  return <div>{isSignedIn ? 'Signed In' : 'Signed Out'}</div>;
}
```

### useUser

#### Before (Clerk)

```tsx
import { useUser } from '@clerk/clerk-react';

function Profile() {
  const { user, isLoaded } = useUser();
  
  if (!isLoaded) return <div>Loading...</div>;
  
  return <div>{user?.firstName}</div>;
}
```

#### After (Vault)

```tsx
import { useUser, useAuth } from '@fantasticauth/react';

function Profile() {
  const { isLoaded } = useAuth();
  const user = useUser();
  
  if (!isLoaded) return <div>Loading...</div>;
  
  return <div>{user?.profile?.name}</div>;
}
```

### useSignIn

#### Before (Clerk)

```tsx
import { useSignIn } from '@clerk/clerk-react';

function SignInForm() {
  const { isLoaded, signIn, setActive } = useSignIn();
  
  const handleSubmit = async (email, password) => {
    const result = await signIn.create({
      identifier: email,
      password,
    });
    
    if (result.status === 'complete') {
      await setActive({ session: result.createdSessionId });
    }
  };
}
```

#### After (Vault)

```tsx
import { useSignIn } from '@fantasticauth/react';

function SignInForm() {
  const { signIn, isLoading, error } = useSignIn();
  
  const handleSubmit = async (email, password) => {
    await signIn({ email, password });
  };
}
```

## Component Migration

### SignIn Component

#### Before (Clerk)

```tsx
import { SignIn } from '@clerk/clerk-react';

<SignIn 
  path="/sign-in"
  routing="path"
  signUpUrl="/sign-up"
  redirectUrl="/dashboard"
/>
```

#### After (Vault)

```tsx
import { SignIn } from '@fantasticauth/react';

<SignIn 
  redirectUrl="/dashboard"
  oauthProviders={['google', 'github']}
/>
```

### SignUp Component

#### Before (Clerk)

```tsx
import { SignUp } from '@clerk/clerk-react';

<SignUp 
  path="/sign-up"
  routing="path"
  signInUrl="/sign-in"
  redirectUrl="/dashboard"
/>
```

#### After (Vault)

```tsx
import { SignUp } from '@fantasticauth/react';

<SignUp 
  redirectUrl="/dashboard"
  oauthProviders={['google', 'github']}
/>
```

### UserButton

#### Before (Clerk)

```tsx
import { UserButton } from '@clerk/clerk-react';

<UserButton 
  afterSignOutUrl="/"
  userProfileUrl="/profile"
/>
```

#### After (Vault)

```tsx
import { UserButton } from '@fantasticauth/react';

<UserButton 
  showName={true}
  showManageAccount={true}
  onSignOut={() => window.location.href = '/'}
  menuItems={[
    { label: 'Profile', onClick: () => router.push('/profile') },
  ]}
/>
```

### UserProfile

#### Before (Clerk)

```tsx
import { UserProfile } from '@clerk/clerk-react';

<UserProfile 
  path="/user-profile"
  routing="path"
/>
```

#### After (Vault)

```tsx
import { UserProfile } from '@fantasticauth/react';

<UserProfile 
  onUpdate={(user) => console.log('Updated:', user)}
/>
```

### OrganizationSwitcher

#### Before (Clerk)

```tsx
import { OrganizationSwitcher } from '@clerk/clerk-react';

<OrganizationSwitcher 
  afterCreateOrganizationUrl="/organization/:id"
/>
```

#### After (Vault)

```tsx
import { OrganizationSwitcher } from '@fantasticauth/react';

<OrganizationSwitcher 
  onSwitch={(org) => console.log('Switched to:', org)}
/>
```

## Control Components

### SignedIn / SignedOut

#### Before (Clerk)

```tsx
import { SignedIn, SignedOut } from '@clerk/clerk-react';

<SignedIn>
  <UserButton />
</SignedIn>

<SignedOut>
  <SignInButton />
</SignedOut>
```

#### After (Vault)

```tsx
import { SignedIn, SignedOut } from '@fantasticauth/react';

<SignedIn>
  <UserButton />
</SignedIn>

<SignedOut>
  <a href="/sign-in">Sign In</a>
</SignedOut>
```

## Protect Component

### Before (Clerk)

```tsx
import { RedirectToSignIn, useAuth } from '@clerk/clerk-react';

function ProtectedPage() {
  const { isSignedIn } = useAuth();
  
  if (!isSignedIn) {
    return <RedirectToSignIn />;
  }
  
  return <div>Protected content</div>;
}
```

### After (Vault)

```tsx
import { Protect } from '@fantasticauth/react';

function ProtectedPage() {
  return (
    <Protect>
      <div>Protected content</div>
    </Protect>
  );
}
```

## Middleware Migration

### Before (Clerk - Next.js)

```tsx
import { authMiddleware } from '@clerk/nextjs';

export default authMiddleware({
  publicRoutes: ['/', '/sign-in', '/sign-up'],
});

export const config = {
  matcher: ['/((?!.*\\..*|_next).*)', '/'],
};
```

### After (Vault - Next.js)

```tsx
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(request: NextRequest) {
  const token = request.cookies.get('fantasticauth_session_token');
  const publicRoutes = ['/', '/sign-in', '/sign-up'];
  
  if (publicRoutes.includes(request.nextUrl.pathname)) {
    return NextResponse.next();
  }
  
  if (!token) {
    return NextResponse.redirect(new URL('/sign-in', request.url));
  }
  
  return NextResponse.next();
}

export const config = {
  matcher: ['/dashboard/:path*', '/profile/:path*'],
};
```

## API Calls

### Before (Clerk)

```tsx
import { useAuth } from '@clerk/clerk-react';

async function fetchData() {
  const { getToken } = useAuth();
  const token = await getToken();
  
  const response = await fetch('/api/data', {
    headers: { Authorization: `Bearer ${token}` },
  });
}
```

### After (Vault)

```tsx
import { useSession } from '@fantasticauth/react';

async function fetchData() {
  const { getToken } = useSession();
  const token = await getToken();
  
  const response = await fetch('/api/data', {
    headers: { Authorization: `Bearer ${token}` },
  });
}
```

## Differences to Note

1. **No routing prop** - Vault components don't handle routing internally
2. **Simpler sign-in flow** - No need to manually call `setActive`
3. **Different user structure** - `user.firstName` → `user.profile.name`
4. **Token getter** - `useAuth().getToken` → `useSession().getToken`

## Checklist

- [ ] Install `@fantasticauth/react`
- [ ] Update environment variables
- [ ] Replace `<ClerkProvider>` with `<VaultProvider>`
- [ ] Update imports from `@clerk/clerk-react` to `@fantasticauth/react`
- [ ] Update `useAuth()` usage
- [ ] Update `useUser()` usage
- [ ] Update `useSignIn()` usage
- [ ] Replace `<SignIn />` props
- [ ] Replace `<SignUp />` props
- [ ] Update `<UserButton />` props
- [ ] Update middleware
- [ ] Test all authentication flows
- [ ] Test OAuth providers
- [ ] Test protected routes
- [ ] Update documentation

## Support

For migration assistance:
- [Vault Documentation](../README.md)
- [GitHub Issues](https://github.com/vault/auth/issues)
- [Discord Community](https://discord.gg/vault)
