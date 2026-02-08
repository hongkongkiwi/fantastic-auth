# Next.js App Router Example

Complete guide to using the Vault React SDK with Next.js App Router.

## Project Structure

```
app/
├── layout.tsx          # Root layout with VaultProvider
├── page.tsx            # Home page
├── providers.tsx       # Client providers
├── sign-in/
│   └── page.tsx        # Sign-in page
├── sign-up/
│   └── page.tsx        # Sign-up page
├── dashboard/
│   └── page.tsx        # Protected dashboard
└── api/
    └── vault/
        └── route.ts    # API route handlers
```

## Installation

```bash
npm install @vault/react
```

## Configuration

### Environment Variables

```bash
# .env.local
NEXT_PUBLIC_VAULT_API_URL=https://api.vault.dev
NEXT_PUBLIC_VAULT_TENANT_ID=your-tenant-id
```

### Providers Component

Create a client-side providers wrapper:

```tsx
// app/providers.tsx
'use client';

import { VaultProvider } from '@vault/react';
import { ReactNode } from 'react';

interface ProvidersProps {
  children: ReactNode;
}

export function Providers({ children }: ProvidersProps) {
  return (
    <VaultProvider
      config={{
        apiUrl: process.env.NEXT_PUBLIC_VAULT_API_URL!,
        tenantId: process.env.NEXT_PUBLIC_VAULT_TENANT_ID!,
      }}
    >
      {children}
    </VaultProvider>
  );
}
```

### Root Layout

```tsx
// app/layout.tsx
import { Providers } from './providers';
import './globals.css';

export const metadata = {
  title: 'My App',
  description: 'Built with Vault',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
```

## Pages

### Home Page

```tsx
// app/page.tsx
import { SignedIn, SignedOut } from '@vault/react';
import Link from 'next/link';

export default function Home() {
  return (
    <main className="container mx-auto p-8">
      <h1 className="text-4xl font-bold mb-8">Welcome</h1>
      
      <SignedOut>
        <div className="space-x-4">
          <Link
            href="/sign-in"
            className="px-4 py-2 bg-blue-600 text-white rounded"
          >
            Sign In
          </Link>
          <Link
            href="/sign-up"
            className="px-4 py-2 border border-blue-600 text-blue-600 rounded"
          >
            Sign Up
          </Link>
        </div>
      </SignedOut>
      
      <SignedIn>
        <Link
          href="/dashboard"
          className="px-4 py-2 bg-blue-600 text-white rounded"
        >
          Go to Dashboard
        </Link>
      </SignedIn>
    </main>
  );
}
```

### Sign In Page

```tsx
// app/sign-in/page.tsx
'use client';

import { SignIn } from '@vault/react';

export default function SignInPage() {
  return (
    <main className="min-h-screen flex items-center justify-center p-4">
      <SignIn
        redirectUrl="/dashboard"
        oauthProviders={['google', 'github']}
        appearance={{
          variables: {
            colorPrimary: '#2563eb',
          },
        }}
      />
    </main>
  );
}
```

### Sign Up Page

```tsx
// app/sign-up/page.tsx
'use client';

import { SignUp } from '@vault/react';

export default function SignUpPage() {
  return (
    <main className="min-h-screen flex items-center justify-center p-4">
      <SignUp
        redirectUrl="/onboarding"
        oauthProviders={['google', 'github']}
        requireName={true}
      />
    </main>
  );
}
```

### Dashboard (Protected)

```tsx
// app/dashboard/page.tsx
'use client';

import { useAuth, UserButton, Protect } from '@vault/react';
import Link from 'next/link';

export default function Dashboard() {
  return (
    <Protect>
      <DashboardContent />
    </Protect>
  );
}

function DashboardContent() {
  const { user } = useAuth();

  return (
    <div className="min-h-screen bg-gray-50">
      <header className="bg-white shadow">
        <div className="container mx-auto px-4 py-4 flex justify-between items-center">
          <h1 className="text-xl font-bold">Dashboard</h1>
          <UserButton showName={true} />
        </div>
      </header>
      
      <main className="container mx-auto px-4 py-8">
        <h2 className="text-2xl font-semibold mb-4">
          Welcome, {user?.profile?.name || user?.email}
        </h2>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="bg-white p-6 rounded-lg shadow">
            <h3 className="font-semibold mb-2">Profile</h3>
            <Link href="/profile" className="text-blue-600">
              Manage Profile →
            </Link>
          </div>
          
          <div className="bg-white p-6 rounded-lg shadow">
            <h3 className="font-semibold mb-2">Settings</h3>
            <Link href="/settings" className="text-blue-600">
              Account Settings →
            </Link>
          </div>
          
          <div className="bg-white p-6 rounded-lg shadow">
            <h3 className="font-semibold mb-2">Security</h3>
            <Link href="/security" className="text-blue-600">
              Security Settings →
            </Link>
          </div>
        </div>
      </main>
    </div>
  );
}
```

### Profile Page

```tsx
// app/profile/page.tsx
'use client';

import { UserProfile, Protect } from '@vault/react';

export default function ProfilePage() {
  return (
    <Protect>
      <main className="container mx-auto px-4 py-8">
        <h1 className="text-2xl font-bold mb-8">Your Profile</h1>
        <UserProfile
          onUpdate={(user) => {
            console.log('Profile updated:', user);
          }}
        />
      </main>
    </Protect>
  );
}
```

## Components

### Header with Navigation

```tsx
// components/Header.tsx
'use client';

import { SignedIn, SignedOut, UserButton } from '@vault/react';
import Link from 'next/link';

export function Header() {
  return (
    <header className="bg-white shadow">
      <nav className="container mx-auto px-4 py-4 flex justify-between items-center">
        <Link href="/" className="text-xl font-bold">
          MyApp
        </Link>
        
        <div className="flex items-center gap-4">
          <SignedIn>
            <Link href="/dashboard" className="text-gray-600 hover:text-gray-900">
              Dashboard
            </Link>
            <UserButton showName={false} />
          </SignedIn>
          
          <SignedOut>
            <Link
              href="/sign-in"
              className="text-gray-600 hover:text-gray-900"
            >
              Sign In
            </Link>
            <Link
              href="/sign-up"
              className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
            >
              Sign Up
            </Link>
          </SignedOut>
        </div>
      </nav>
    </header>
  );
}
```

### Loading State

```tsx
// components/Loading.tsx
'use client';

import { useAuth } from '@vault/react';

export function Loading({ children }: { children: React.ReactNode }) {
  const { isLoaded } = useAuth();

  if (!isLoaded) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600" />
      </div>
    );
  }

  return <>{children}</>;
}
```

## Middleware

Protect routes using Next.js middleware:

```tsx
// middleware.ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(request: NextRequest) {
  const token = request.cookies.get('vault_session_token');
  const { pathname } = request.nextUrl;

  // Public routes
  const publicRoutes = ['/', '/sign-in', '/sign-up', '/forgot-password'];
  
  if (publicRoutes.includes(pathname)) {
    return NextResponse.next();
  }

  // Protected routes require token
  if (!token) {
    return NextResponse.redirect(new URL('/sign-in', request.url));
  }

  return NextResponse.next();
}

export const config = {
  matcher: ['/dashboard/:path*', '/profile/:path*', '/settings/:path*'],
};
```

## Server Components

Use server components where possible:

```tsx
// app/dashboard/layout.tsx (Server Component)
import { Header } from '@/components/Header';

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="min-h-screen bg-gray-50">
      <Header />
      <main className="container mx-auto px-4 py-8">
        {children}
      </main>
    </div>
  );
}
```

## Error Handling

Create an error boundary:

```tsx
// components/ErrorBoundary.tsx
'use client';

import { Component, ErrorInfo, ReactNode } from 'react';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
  };

  public static getDerivedStateFromError(): State {
    return { hasError: true };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('Uncaught error:', error, errorInfo);
  }

  public render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen flex items-center justify-center">
          <div className="text-center">
            <h2 className="text-2xl font-bold mb-4">Something went wrong</h2>
            <button
              onClick={() => this.setState({ hasError: false })}
              className="px-4 py-2 bg-blue-600 text-white rounded"
            >
              Try again
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
```

## Complete Example

```tsx
// app/layout.tsx with all features
import { Providers } from './providers';
import { ErrorBoundary } from '@/components/ErrorBoundary';
import { Loading } from '@/components/Loading';
import './globals.css';

export const metadata = {
  title: 'My App',
  description: 'Built with Vault',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>
        <ErrorBoundary>
          <Providers>
            <Loading>{children}</Loading>
          </Providers>
        </ErrorBoundary>
      </body>
    </html>
  );
}
```

## TypeScript

Ensure proper types:

```ts
// types/env.d.ts
declare namespace NodeJS {
  interface ProcessEnv {
    NEXT_PUBLIC_VAULT_API_URL: string;
    NEXT_PUBLIC_VAULT_TENANT_ID: string;
  }
}
```

## Best Practices

1. **Use `'use client'`** for components using Vault hooks
2. **Keep providers.tsx** as a client component
3. **Use middleware** for route protection when possible
4. **Create reusable components** like Header and Loading
5. **Handle loading states** with `isLoaded` check

## See Also

- [Next.js Documentation](https://nextjs.org/docs)
- [Components](../components/README.md) - Component documentation
- [Hooks](../hooks/README.md) - Hook documentation
