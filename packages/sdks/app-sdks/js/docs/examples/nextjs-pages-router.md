# Next.js Pages Router Example

Using Vault with Next.js Pages Router.

## Setup

### Install

```bash
npm install @fantasticauth/react
```

### Environment Variables

```bash
NEXT_PUBLIC_VAULT_API_URL=https://api.vault.dev
NEXT_PUBLIC_VAULT_TENANT_ID=your-tenant-id
```

### _app.tsx

```tsx
import { VaultProvider } from '@fantasticauth/react';
import type { AppProps } from 'next/app';

export default function MyApp({ Component, pageProps }: AppProps) {
  return (
    <VaultProvider
      config={{
        apiUrl: process.env.NEXT_PUBLIC_VAULT_API_URL!,
        tenantId: process.env.NEXT_PUBLIC_VAULT_TENANT_ID!,
      }}
      initialUser={pageProps.user}
      initialSessionToken={pageProps.sessionToken}
    >
      <Component {...pageProps} />
    </VaultProvider>
  );
}
```

## Pages

### Sign In Page

```tsx
// pages/sign-in.tsx
import { SignIn } from '@fantasticauth/react';

export default function SignInPage() {
  return (
    <div className="min-h-screen flex items-center justify-center">
      <SignIn redirectUrl="/dashboard" />
    </div>
  );
}
```

### Dashboard Page

```tsx
// pages/dashboard.tsx
import { Protect, UserButton, useAuth } from '@fantasticauth/react';

export default function Dashboard() {
  return (
    <Protect>
      <div>
        <header className="flex justify-between items-center p-4">
          <h1>Dashboard</h1>
          <UserButton />
        </header>
        <main className="p-4">
          <DashboardContent />
        </main>
      </div>
    </Protect>
  );
}

function DashboardContent() {
  const { user } = useAuth();
  return <p>Welcome, {user?.email}</p>;
}
```

## Server-Side Props

```tsx
// pages/dashboard.tsx
import { GetServerSideProps } from 'next';

export const getServerSideProps: GetServerSideProps = async ({ req }) => {
  const token = req.cookies.fantasticauth_session_token;
  
  if (!token) {
    return {
      redirect: {
        destination: '/sign-in',
        permanent: false,
      },
    };
  }
  
  // Validate token and get user
  // const user = await validateToken(token);
  
  return {
    props: {
      // user,
      // sessionToken: token,
    },
  };
};
```

## See Also

- [Next.js App Router](./nextjs-app-router.md)
