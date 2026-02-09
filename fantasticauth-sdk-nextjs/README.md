# @vault/nextjs

Next.js SDK for Vault - Authentication and identity management with first-class support for the Next.js App Router.

## Features

- 🔐 **Server Component Support** - Auth checks in React Server Components
- 🌐 **Edge Middleware** - Protect routes at the edge
- ⚛️ **Client Components** - React hooks for client-side auth state
- 🛣️ **API Routes** - Authenticated route handlers
- 🔄 **Automatic Token Refresh** - Seamless session management
- 🎯 **TypeScript** - Full type safety

## Installation

```bash
npm install @vault/nextjs
# or
yarn add @vault/nextjs
# or
pnpm add @vault/nextjs
```

## Quick Start

### 1. Configure Environment Variables

```env
# .env.local
VAULT_API_URL=https://api.vault.example.com
VAULT_TENANT_ID=your-tenant-id
VAULT_SECRET_KEY=your-secret-key  # Server-side only

# Client-side (public)
NEXT_PUBLIC_VAULT_API_URL=https://api.vault.example.com
NEXT_PUBLIC_VAULT_TENANT_ID=your-tenant-id
NEXT_PUBLIC_VAULT_PUBLISHABLE_KEY=your-publishable-key
```

### 2. Add VaultProvider

```tsx
// app/layout.tsx
import { VaultProvider } from '@vault/nextjs';

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>
        <VaultProvider
          apiUrl={process.env.NEXT_PUBLIC_VAULT_API_URL!}
          tenantId={process.env.NEXT_PUBLIC_VAULT_TENANT_ID!}
          publishableKey={process.env.NEXT_PUBLIC_VAULT_PUBLISHABLE_KEY}
        >
          {children}
        </VaultProvider>
      </body>
    </html>
  );
}
```

### 3. Protect Routes with Middleware

```tsx
// middleware.ts
import { authMiddleware } from '@vault/nextjs/server';

export default authMiddleware({
  publicRoutes: ['/', '/sign-in', '/sign-up', '/forgot-password'],
  apiRoutes: ['/api/webhooks/(.*)'],
  signInUrl: '/sign-in',
});

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
```

### 4. Use in Server Components

```tsx
// app/dashboard/page.tsx
import { auth, currentUser } from '@vault/nextjs/server';
import { redirect } from 'next/navigation';

export default async function Dashboard() {
  const { userId, isSignedIn } = await auth();
  const user = await currentUser();

  if (!isSignedIn) {
    redirect('/sign-in');
  }

  return (
    <div>
      <h1>Welcome, {user?.name}!</h1>
      <p>User ID: {userId}</p>
    </div>
  );
}
```

### 5. Use in Client Components

```tsx
// app/components/Profile.tsx
'use client';

import { useUser, useAuth } from '@vault/nextjs/client';

export function Profile() {
  const { user, isLoaded } = useUser();
  const { signOut } = useAuth();

  if (!isLoaded) return <div>Loading...</div>;
  if (!user) return <div>Not signed in</div>;

  return (
    <div>
      <h2>{user.name}</h2>
      <p>{user.email}</p>
      <button onClick={() => signOut()}>Sign Out</button>
    </div>
  );
}
```

## API Reference

### Server-Side (`@vault/nextjs/server`)

#### `auth()`

Validates the current session and returns auth state.

```tsx
import { auth } from '@vault/nextjs/server';

const { userId, session, orgId, orgRole, isSignedIn } = await auth();
```

#### `currentUser()`

Fetches the full user object for the authenticated user.

```tsx
import { currentUser } from '@vault/nextjs/server';

const user = await currentUser();
```

#### `getToken()`

Returns the session token for making authenticated API calls.

```tsx
import { getToken } from '@vault/nextjs/server';

const token = await getToken();
```

#### `authMiddleware(options)`

Edge middleware for protecting routes.

```tsx
import { authMiddleware } from '@vault/nextjs/server';

export default authMiddleware({
  // Routes that don't require auth
  publicRoutes: ['/', '/sign-in', '/sign-up'],
  
  // API routes that are public
  apiRoutes: ['/api/webhooks/(.*)'],
  
  // Sign-in page URL
  signInUrl: '/sign-in',
  
  // Redirect after sign-in
  afterSignInUrl: '/dashboard',
});
```

Options:

| Option | Type | Description |
|--------|------|-------------|
| `publicRoutes` | `string[]` | Routes that don't require authentication |
| `protectedRoutes` | `string[]` | Routes that require authentication (alternative to publicRoutes) |
| `apiRoutes` | `string[]` | Public API routes |
| `signInUrl` | `string` | URL to redirect to when auth is required |
| `afterSignInUrl` | `string` | URL to redirect to after sign-in |
| `debug` | `boolean` | Enable debug logging |

### Client-Side (`@vault/nextjs/client`)

#### `useAuth()`

Access authentication state and methods.

```tsx
import { useAuth } from '@vault/nextjs/client';

const { 
  isLoaded,      // Boolean indicating if auth state is loaded
  isSignedIn,    // Boolean indicating if user is signed in
  userId,        // Current user's ID
  orgId,         // Current organization ID
  orgRole,       // Current organization role
  signOut,       // Function to sign out
  getToken,      // Function to get session token
} = useAuth();
```

#### `useUser()`

Access the current user object.

```tsx
import { useUser } from '@vault/nextjs/client';

const { user, isLoaded, isSignedIn } = useUser();
```

#### `useSession()`

Access the current session.

```tsx
import { useSession } from '@vault/nextjs/client';

const { session, isLoaded } = useSession();
```

#### `useOrganization()`

Access organization context.

```tsx
import { useOrganization } from '@vault/nextjs/client';

const { orgId, orgRole, isLoaded, isSignedIn } = useOrganization();
```

### API Routes (`@vault/nextjs/api`)

#### `withAuth(handler, options)`

Wrap a route handler with authentication.

```tsx
import { withAuth } from '@vault/nextjs/api';

export const GET = withAuth(
  async (request, { auth, user, token }) => {
    return Response.json({ user });
  },
  { requireAuth: true }
);
```

#### `createRouteHandler(handlers, options)`

Create a route handler with multiple methods.

```tsx
import { createRouteHandler } from '@vault/nextjs/api';

export const { GET, POST, DELETE } = createRouteHandler({
  GET: async (req, { auth }) => Response.json({ items: [] }),
  POST: async (req, { auth }) => Response.json({ created: true }),
  DELETE: async (req, { auth }) => Response.json({ deleted: true }),
}, { requireAuth: true });
```

## Examples

### Protecting API Routes

```tsx
// app/api/protected/route.ts
import { withAuth } from '@vault/nextjs/api';

export const GET = withAuth(
  async (request, { auth, user, token }) => {
    // Make authenticated API call
    const data = await fetch('https://api.example.com/data', {
      headers: { Authorization: `Bearer ${token}` },
    });

    return Response.json(await data.json());
  }
);
```

### Server Actions with Auth

```tsx
// app/actions.ts
'use server';

import { auth } from '@vault/nextjs/server';

export async function updateProfile(formData: FormData) {
  const { userId, isSignedIn } = await auth();

  if (!isSignedIn) {
    throw new Error('Unauthorized');
  }

  // Update profile...
}
```

### Organization Role Checks

```tsx
// app/admin/page.tsx
import { auth } from '@vault/nextjs/server';
import { redirect } from 'next/navigation';

export default async function AdminPage() {
  const { orgRole } = await auth();

  if (orgRole !== 'admin' && orgRole !== 'owner') {
    redirect('/');
  }

  return <div>Admin Panel</div>;
}
```

Client-side:

```tsx
'use client';

import { useHasRole } from '@vault/nextjs/client';

export function AdminOnly({ children }: { children: React.ReactNode }) {
  const hasAdminRole = useHasRole(['admin', 'owner']);

  if (!hasAdminRole) {
    return <div>Access denied</div>;
  }

  return <>{children}</>;
}
```

### Handling Webhooks

```tsx
// app/api/webhooks/vault/route.ts
import { handleWebhook } from '@vault/nextjs/api';

export async function POST(request: Request) {
  return handleWebhook(request, {
    'user.created': async (event) => {
      console.log('User created:', event.data.userId);
      return Response.json({ processed: true });
    },
    'user.updated': async (event) => {
      console.log('User updated:', event.data.userId);
      return Response.json({ processed: true });
    },
    'session.created': async (event) => {
      console.log('Session created:', event.data.sessionId);
      return Response.json({ processed: true });
    },
  });
}
```

## Runtime Support

- **Edge Runtime**: Full support for middleware and edge functions
- **Node.js Runtime**: Full support for server components and API routes

## TypeScript

Full TypeScript support with exported types:

```tsx
import type { 
  User, 
  Session, 
  AuthResult, 
  AuthMiddlewareOptions 
} from '@vault/nextjs';
```

## License

MIT
