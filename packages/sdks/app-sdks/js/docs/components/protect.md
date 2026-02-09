# Protect Component

The `Protect` component provides route protection with authentication and role-based access control.

## Overview

The Protect component:
- Blocks access for unauthenticated users
- Supports role-based access control
- Supports permission-based access control
- Shows loading state while auth initializes
- Provides customizable fallback UI

## Basic Usage

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

## Props

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `children` | `React.ReactNode` | - | Content to render when authorized |
| `fallback` | `React.ReactNode` | - | Custom fallback for unauthorized users |
| `role` | `string` | - | Required organization role |
| `permission` | `string` | - | Required permission |
| `loading` | `React.ReactNode` | - | Custom loading component |

## Examples

### Basic Protection

```tsx
<Protect>
  <Dashboard />
</Protect>
```

### With Custom Fallback

```tsx
<Protect
  fallback={
    <div>
      <p>Please sign in to access this page.</p>
      <a href="/sign-in">Sign In</a>
    </div>
  }
>
  <Dashboard />
</Protect>
```

### Role-Based Protection

```tsx
<Protect role="admin">
  <AdminPanel />
</Protect>
```

### Permission-Based Protection

```tsx
<Protect permission="org:write">
  <EditPage />
</Protect>
```

### Custom Loading State

```tsx
<Protect
  loading={<div>Loading authentication...</div>}
>
  <Dashboard />
</Protect>
```

### Combined Access Control

```tsx
<Protect role="admin" permission="org:delete">
  <DangerousOperation />
</Protect>
```

## Fallback Behavior

When a user is not authorized:

1. **Not signed in**: Shows fallback or default "Sign in required" message
2. **Wrong role**: Shows "Access denied" message
3. **Wrong permission**: Shows "Access denied" message

```tsx
<Protect
  fallback={
    <div className="unauthorized">
      <h2>🔒 Access Denied</h2>
      <p>You don't have permission to view this page.</p>
      <a href="/">Go Home</a>
    </div>
  }
>
  <ProtectedContent />
</Protect>
```

## Server-Side Rendering

The Protect component works with SSR:

```tsx
// pages/dashboard.tsx (Next.js)
import { Protect } from '@fantasticauth/react';

export default function DashboardPage() {
  return (
    <Protect>
      <Dashboard />
    </Protect>
  );
}
```

## Alternative: RedirectToSignIn

For automatic redirection:

```tsx
import { RedirectToSignIn, useAuth } from '@fantasticauth/react';

function ProtectedPage() {
  const { isLoaded, isSignedIn } = useAuth();

  if (!isLoaded) return <div>Loading...</div>;
  if (!isSignedIn) return <RedirectToSignIn redirectUrl="/protected" />;

  return <div>Protected content</div>;
}
```

## Testing

```tsx
import { render, screen } from '@testing-library/react';
import { Protect } from '@fantasticauth/react';

test('renders children when authenticated', () => {
  render(
    <VaultProvider config={config} initialUser={mockUser}>
      <Protect>
        <div>Protected</div>
      </Protect>
    </VaultProvider>
  );
  
  expect(screen.getByText('Protected')).toBeInTheDocument();
});
```

## See Also

- [SignedIn / SignedOut](./control-components.md) - Conditional rendering
- [useAuth Hook](../hooks/use-auth.md) - Authentication state
