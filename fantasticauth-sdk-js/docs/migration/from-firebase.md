# Migrating from Firebase Auth

Guide for migrating your React application from Firebase Auth to Vault.

## Overview

Firebase Auth and Vault take different approaches to authentication. This guide helps you transition from Firebase's imperative API to Vault's declarative React components.

## Feature Comparison

| Feature | Firebase Auth | Vault |
|---------|---------------|-------|
| React SDK | `firebase/auth` | `@vault/react` |
| Provider | Context via `onAuthStateChanged` | `<VaultProvider>` |
| Auth State | `useAuthState` hook | `useAuth()` hook |
| Sign In | `signInWithEmailAndPassword()` | `signIn()` / `<SignIn />` |
| Sign Up | `createUserWithEmailAndPassword()` | `signUp()` / `<SignUp />` |
| OAuth | `signInWithPopup()` | `signInWithOAuth()` |
| User | `currentUser` | `user` from hook |
| UI Components | None (build yourself) | Pre-built components |

## Installation

### Remove Firebase

```bash
npm uninstall firebase
```

### Install Vault

```bash
npm install @vault/react
```

## Configuration

### Before (Firebase)

```tsx
// firebase.ts
import { initializeApp } from 'firebase/app';
import { getAuth } from 'firebase/auth';

const firebaseConfig = {
  apiKey: 'your-api-key',
  authDomain: 'your-project.firebaseapp.com',
  projectId: 'your-project',
  // ...
};

const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);
```

### After (Vault)

```tsx
// No setup file needed
// Just configure the provider in your app
```

Environment variables:

```bash
NEXT_PUBLIC_VAULT_API_URL=https://api.vault.dev
NEXT_PUBLIC_VAULT_TENANT_ID=your-tenant-id
```

## Provider Migration

### Before (Firebase)

```tsx
import { auth } from './firebase';
import { onAuthStateChanged } from 'firebase/auth';
import { useState, useEffect } from 'react';

function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, (user) => {
      setUser(user);
      setLoading(false);
    });

    return unsubscribe;
  }, []);

  if (loading) return <div>Loading...</div>;

  return (
    <AuthContext.Provider value={{ user }}>
      {children}
    </AuthContext.Provider>
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

## Auth State Migration

### Before (Firebase)

```tsx
import { useAuthState } from 'react-firebase-hooks/auth';
import { auth } from './firebase';

function Component() {
  const [user, loading, error] = useAuthState(auth);
  
  if (loading) return <div>Loading...</div>;
  if (error) return <div>Error: {error.message}</div>;
  
  return <div>{user ? `Hello ${user.email}` : 'Not signed in'}</div>;
}
```

### After (Vault)

```tsx
import { useAuth } from '@vault/react';

function Component() {
  const { isLoaded, isSignedIn, user } = useAuth();
  
  if (!isLoaded) return <div>Loading...</div>;
  
  return <div>{isSignedIn ? `Hello ${user?.email}` : 'Not signed in'}</div>;
}
```

## Email/Password Sign In

### Before (Firebase)

```tsx
import { signInWithEmailAndPassword } from 'firebase/auth';
import { auth } from './firebase';
import { useState } from 'react';

function SignInForm() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      await signInWithEmailAndPassword(auth, email, password);
    } catch (err) {
      setError(err.message);
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
      {error && <p>{error}</p>}
      <button type="submit">Sign In</button>
    </form>
  );
}
```

### After (Vault)

Using pre-built component:

```tsx
import { SignIn } from '@vault/react';

function SignInPage() {
  return <SignIn redirectUrl="/dashboard" />;
}
```

Using hook:

```tsx
import { useSignIn } from '@vault/react';
import { useState } from 'react';

function SignInForm() {
  const { signIn, isLoading, error } = useSignIn();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    await signIn({ email, password });
  };

  return (
    <form onSubmit={handleSubmit}>
      <input
        type="email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        disabled={isLoading}
      />
      <input
        type="password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        disabled={isLoading}
      />
      {error && <p>{error.message}</p>}
      <button type="submit" disabled={isLoading}>
        {isLoading ? 'Signing in...' : 'Sign In'}
      </button>
    </form>
  );
}
```

## Email/Password Sign Up

### Before (Firebase)

```tsx
import { createUserWithEmailAndPassword, updateProfile } from 'firebase/auth';
import { auth } from './firebase';

async function signUp(email, password, displayName) {
  const { user } = await createUserWithEmailAndPassword(auth, email, password);
  await updateProfile(user, { displayName });
}
```

### After (Vault)

Using pre-built component:

```tsx
import { SignUp } from '@vault/react';

function SignUpPage() {
  return <SignUp redirectUrl="/dashboard" requireName={true} />;
}
```

Using hook:

```tsx
import { useSignUp } from '@vault/react';

function SignUpForm() {
  const { signUp, isLoading, error } = useSignUp();

  const handleSubmit = async (email, password, name) => {
    await signUp({ email, password, name });
  };
}
```

## OAuth Sign In

### Before (Firebase)

```tsx
import { signInWithPopup, GoogleAuthProvider } from 'firebase/auth';
import { auth } from './firebase';

async function signInWithGoogle() {
  const provider = new GoogleAuthProvider();
  await signInWithPopup(auth, provider);
}
```

### After (Vault)

```tsx
import { useAuth } from '@vault/react';

function GoogleSignIn() {
  const { signInWithOAuth } = useAuth();

  return (
    <button onClick={() => signInWithOAuth({ provider: 'google' })}>
      Sign in with Google
    </button>
  );
}
```

## Sign Out

### Before (Firebase)

```tsx
import { signOut } from 'firebase/auth';
import { auth } from './firebase';

async function logOut() {
  await signOut(auth);
}
```

### After (Vault)

```tsx
import { useAuth } from '@vault/react';

function SignOutButton() {
  const { signOut } = useAuth();

  return <button onClick={signOut}>Sign Out</button>;
}
```

## Protected Routes

### Before (Firebase)

```tsx
import { useAuthState } from 'react-firebase-hooks/auth';
import { auth } from './firebase';
import { Navigate } from 'react-router-dom';

function ProtectedRoute({ children }) {
  const [user, loading] = useAuthState(auth);

  if (loading) return <div>Loading...</div>;
  if (!user) return <Navigate to="/login" />;

  return children;
}
```

### After (Vault)

```tsx
import { Protect } from '@vault/react';

function ProtectedRoute({ children }) {
  return <Protect>{children}</Protect>;
}
```

## User Profile

### Before (Firebase)

```tsx
import { updateProfile, updateEmail, updatePassword } from 'firebase/auth';
import { auth } from './firebase';

async function updateUserProfile(displayName, photoURL) {
  await updateProfile(auth.currentUser, { displayName, photoURL });
}

async function updateUserEmail(email) {
  await updateEmail(auth.currentUser, email);
}

async function updateUserPassword(password) {
  await updatePassword(auth.currentUser, password);
}
```

### After (Vault)

Using pre-built component:

```tsx
import { UserProfile } from '@vault/react';

function ProfilePage() {
  return <UserProfile />;
}
```

Using hook:

```tsx
import { useUserManager } from '@vault/react';

function ProfileEditor() {
  const { update, changePassword } = useUserManager();

  const handleUpdate = async (data) => {
    await update({ profile: data });
  };

  const handleChangePassword = async (current, newPassword) => {
    await changePassword(current, newPassword);
  };
}
```

## ID Tokens

### Before (Firebase)

```tsx
import { getIdToken } from 'firebase/auth';
import { auth } from './firebase';

async function getToken() {
  const user = auth.currentUser;
  if (user) {
    return await getIdToken(user);
  }
  return null;
}
```

### After (Vault)

```tsx
import { useSession } from '@vault/react';

async function fetchWithAuth() {
  const { getToken } = useSession();
  const token = await getToken();
  
  return fetch('/api/data', {
    headers: { Authorization: `Bearer ${token}` },
  });
}
```

## Differences to Note

1. **Pre-built UI** - Firebase has no UI components; Vault provides complete forms
2. **State management** - Firebase uses callbacks; Vault uses React context
3. **User object** - Firebase: `user.displayName`; Vault: `user.profile.name`
4. **Token refresh** - Firebase handles automatically; Vault handles automatically
5. **OAuth flow** - Firebase uses popups; Vault uses redirects
6. **Error handling** - Firebase throws errors; Vault provides error states

## Migration Checklist

- [ ] Install `@vault/react`
- [ ] Remove Firebase dependencies
- [ ] Delete Firebase config file
- [ ] Set up environment variables
- [ ] Replace auth context with `<VaultProvider>`
- [ ] Update auth state hooks (`useAuthState` → `useAuth`)
- [ ] Replace sign-in forms with `<SignIn />` component
- [ ] Replace sign-up forms with `<SignUp />` component
- [ ] Update OAuth sign-in methods
- [ ] Replace sign-out methods
- [ ] Update protected routes to use `<Protect />`
- [ ] Add `<UserButton />` for navigation
- [ ] Add `<UserProfile />` for profile management
- [ ] Update API token retrieval
- [ ] Update user property access
- [ ] Test all authentication flows
- [ ] Remove Firebase initialization code

## Key Benefits of Vault

1. **Pre-built UI** - Complete forms with styling
2. **Simpler code** - Less boilerplate
3. **Built-in features** - Magic links, MFA, organizations
4. **Better DX** - React-first design
5. **Type safety** - Full TypeScript support

## Support

For migration assistance:
- [Vault Documentation](../README.md)
- [GitHub Issues](https://github.com/vault/auth/issues)
