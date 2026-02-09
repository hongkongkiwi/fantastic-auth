# Control Components

Control components for conditional rendering based on authentication state.

## SignedIn

Renders children only when user is signed in.

### Usage

```tsx
import { SignedIn } from '@fantasticauth/react';

function Header() {
  return (
    <header>
      <SignedIn>
        <UserButton />
        <a href="/dashboard">Dashboard</a>
      </SignedIn>
    </header>
  );
}
```

### Props

| Prop | Type | Description |
|------|------|-------------|
| `children` | `React.ReactNode` | Content to render when signed in |

## SignedOut

Renders children only when user is signed out.

### Usage

```tsx
import { SignedOut } from '@fantasticauth/react';

function Header() {
  return (
    <header>
      <SignedOut>
        <a href="/sign-in">Sign In</a>
        <a href="/sign-up">Sign Up</a>
      </SignedOut>
    </header>
  );
}
```

### Props

| Prop | Type | Description |
|------|------|-------------|
| `children` | `React.ReactNode` | Content to render when signed out |

## RequireAuth

Renders children only when user is signed in, with fallback support.

### Usage

```tsx
import { RequireAuth } from '@fantasticauth/react';

function ProfileSection() {
  return (
    <RequireAuth
      fallback={<p>Please <a href="/sign-in">sign in</a> to view your profile</p>}
      loading={<div>Loading...</div>}
    >
      <UserProfile />
    </RequireAuth>
  );
}
```

### Props

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `children` | `React.ReactNode` | - | Content to render when authenticated |
| `fallback` | `React.ReactNode` | - | Content for unauthenticated users |
| `loading` | `React.ReactNode` | - | Loading state while auth initializes |

## Complete Example

```tsx
import { SignedIn, SignedOut, UserButton } from '@fantasticauth/react';

function Navigation() {
  return (
    <nav>
      <a href="/">Home</a>
      
      <SignedIn>
        <a href="/dashboard">Dashboard</a>
        <a href="/profile">Profile</a>
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

## Comparison

| Component | Renders When | Use Case |
|-----------|--------------|----------|
| `<SignedIn>` | User is signed in | Navigation items, buttons |
| `<SignedOut>` | User is signed out | Login/signup links |
| `<RequireAuth>` | User is signed in (with fallback) | Protected sections |
| `<Protect>` | User is signed in (with defaults) | Protected pages |

## See Also

- [Protect Component](./protect.md) - Route protection
- [useAuth Hook](../hooks/use-auth.md) - Authentication hook
