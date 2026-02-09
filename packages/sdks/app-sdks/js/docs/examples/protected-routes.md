# Protected Routes Example

This guide shows different patterns for protecting routes in your application.

## Using the Protect Component

The simplest way to protect routes:

```tsx
import { Protect } from '@fantasticauth/react';

function Dashboard() {
  return (
    <Protect>
      <div>
        <h1>Dashboard</h1>
        <p>Only visible to signed-in users</p>
      </div>
    </Protect>
  );
}
```

## Using useAuth Hook

For more control:

```tsx
import { useAuth } from '@fantasticauth/react';
import { Navigate } from 'react-router-dom';

function ProtectedRoute({ children }) {
  const { isLoaded, isSignedIn } = useAuth();

  if (!isLoaded) {
    return <div>Loading...</div>;
  }

  if (!isSignedIn) {
    return <Navigate to="/sign-in" replace />;
  }

  return children;
}
```

## Next.js Middleware

Protect routes at the edge:

```tsx
// middleware.ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(request: NextRequest) {
  const token = request.cookies.get('fantasticauth_session_token');
  
  if (!token && !request.nextUrl.pathname.startsWith('/sign-in')) {
    return NextResponse.redirect(new URL('/sign-in', request.url));
  }
  
  return NextResponse.next();
}

export const config = {
  matcher: ['/dashboard/:path*', '/profile/:path*'],
};
```

## Role-Based Protection

Protect routes based on user role:

```tsx
import { Protect } from '@fantasticauth/react';

function AdminPanel() {
  return (
    <Protect role="admin" fallback={<p>Admin access required</p>}>
      <div>
        <h1>Admin Panel</h1>
      </div>
    </Protect>
  );
}
```

## See Also

- [Protect Component](../components/protect.md)
- [useAuth Hook](../hooks/use-auth.md)
