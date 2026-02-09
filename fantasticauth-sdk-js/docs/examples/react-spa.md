# React SPA Example

Complete guide to using the Vault React SDK in a single-page application (SPA).

## Project Setup

### Create Project

```bash
# With Vite
npm create vite@latest my-app -- --template react-ts

# With Create React App
npx create-react-app my-app --template typescript
```

### Install Dependencies

```bash
npm install @vault/react
npm install react-router-dom  # For routing
```

## Project Structure

```
src/
├── main.tsx              # App entry point
├── App.tsx               # Root component
├── components/
│   ├── Header.tsx        # Navigation header
│   ├── ProtectedRoute.tsx # Route protection
│   └── Loading.tsx       # Loading spinner
├── pages/
│   ├── Home.tsx          # Home page
│   ├── SignIn.tsx        # Sign in page
│   ├── SignUp.tsx        # Sign up page
│   ├── Dashboard.tsx     # Protected dashboard
│   └── Profile.tsx       # User profile
├── hooks/
│   └── useAuthCheck.ts   # Custom auth hook
└── styles/
    └── globals.css       # Global styles
```

## Configuration

### Environment Variables

Create `.env` file:

```bash
# .env
VITE_VAULT_API_URL=https://api.vault.dev
VITE_VAULT_TENANT_ID=your-tenant-id
```

### Main Entry

```tsx
// src/main.tsx
import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import { VaultProvider } from '@vault/react';
import App from './App';
import './styles/globals.css';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <BrowserRouter>
      <VaultProvider
        config={{
          apiUrl: import.meta.env.VITE_VAULT_API_URL,
          tenantId: import.meta.env.VITE_VAULT_TENANT_ID,
        }}
      >
        <App />
      </VaultProvider>
    </BrowserRouter>
  </React.StrictMode>
);
```

### App Component

```tsx
// src/App.tsx
import { Routes, Route } from 'react-router-dom';
import { Header } from './components/Header';
import { ProtectedRoute } from './components/ProtectedRoute';
import { Home } from './pages/Home';
import { SignIn } from './pages/SignIn';
import { SignUp } from './pages/SignUp';
import { Dashboard } from './pages/Dashboard';
import { Profile } from './pages/Profile';

function App() {
  return (
    <div className="min-h-screen bg-gray-50">
      <Header />
      <main>
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/sign-in" element={<SignIn />} />
          <Route path="/sign-up" element={<SignUp />} />
          <Route
            path="/dashboard"
            element={
              <ProtectedRoute>
                <Dashboard />
              </ProtectedRoute>
            }
          />
          <Route
            path="/profile"
            element={
              <ProtectedRoute>
                <Profile />
              </ProtectedRoute>
            }
          />
        </Routes>
      </main>
    </div>
  );
}

export default App;
```

## Components

### Header

```tsx
// src/components/Header.tsx
import { SignedIn, SignedOut, UserButton } from '@vault/react';
import { Link } from 'react-router-dom';

export function Header() {
  return (
    <header className="bg-white shadow">
      <nav className="container mx-auto px-4 py-4 flex justify-between items-center">
        <Link to="/" className="text-xl font-bold text-gray-900">
          MyApp
        </Link>
        
        <div className="flex items-center gap-4">
          <SignedIn>
            <Link to="/dashboard" className="text-gray-600 hover:text-gray-900">
              Dashboard
            </Link>
            <UserButton showName={false} />
          </SignedIn>
          
          <SignedOut>
            <Link to="/sign-in" className="text-gray-600 hover:text-gray-900">
              Sign In
            </Link>
            <Link
              to="/sign-up"
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

### ProtectedRoute

```tsx
// src/components/ProtectedRoute.tsx
import { Navigate } from 'react-router-dom';
import { useAuth } from '@vault/react';

interface ProtectedRouteProps {
  children: React.ReactNode;
}

export function ProtectedRoute({ children }: ProtectedRouteProps) {
  const { isLoaded, isSignedIn } = useAuth();

  if (!isLoaded) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600" />
      </div>
    );
  }

  if (!isSignedIn) {
    return <Navigate to="/sign-in" replace />;
  }

  return <>{children}</>;
}
```

### Loading

```tsx
// src/components/Loading.tsx
export function Loading() {
  return (
    <div className="min-h-screen flex items-center justify-center">
      <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600" />
    </div>
  );
}
```

## Pages

### Home

```tsx
// src/pages/Home.tsx
import { SignedIn, SignedOut } from '@vault/react';
import { Link } from 'react-router-dom';

export function Home() {
  return (
    <div className="container mx-auto px-4 py-16">
      <div className="text-center max-w-2xl mx-auto">
        <h1 className="text-4xl font-bold mb-6">
          Welcome to MyApp
        </h1>
        <p className="text-xl text-gray-600 mb-8">
          A secure application built with Vault authentication.
        </p>
        
        <SignedOut>
          <div className="space-x-4">
            <Link
              to="/sign-in"
              className="px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
            >
              Get Started
            </Link>
          </div>
        </SignedOut>
        
        <SignedIn>
          <Link
            to="/dashboard"
            className="px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
          >
            Go to Dashboard
          </Link>
        </SignedIn>
      </div>
    </div>
  );
}
```

### Sign In

```tsx
// src/pages/SignIn.tsx
import { SignIn as VaultSignIn } from '@vault/react';

export function SignIn() {
  return (
    <div className="min-h-[calc(100vh-64px)] flex items-center justify-center p-4">
      <VaultSignIn
        redirectUrl="/dashboard"
        oauthProviders={['google', 'github']}
        appearance={{
          variables: {
            colorPrimary: '#2563eb',
            borderRadius: '0.5rem',
          },
        }}
      />
    </div>
  );
}
```

### Sign Up

```tsx
// src/pages/SignUp.tsx
import { SignUp as VaultSignUp } from '@vault/react';

export function SignUp() {
  return (
    <div className="min-h-[calc(100vh-64px)] flex items-center justify-center p-4">
      <VaultSignUp
        redirectUrl="/dashboard"
        oauthProviders={['google', 'github']}
        requireName={true}
        appearance={{
          variables: {
            colorPrimary: '#2563eb',
            borderRadius: '0.5rem',
          },
        }}
      />
    </div>
  );
}
```

### Dashboard

```tsx
// src/pages/Dashboard.tsx
import { useAuth, UserButton } from '@vault/react';
import { Link } from 'react-router-dom';

export function Dashboard() {
  const { user } = useAuth();

  return (
    <div className="container mx-auto px-4 py-8">
      <h1 className="text-3xl font-bold mb-8">
        Welcome, {user?.profile?.name || user?.email}
      </h1>
      
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        <div className="bg-white p-6 rounded-lg shadow">
          <h2 className="text-xl font-semibold mb-2">Profile</h2>
          <p className="text-gray-600 mb-4">
            Manage your personal information
          </p>
          <Link
            to="/profile"
            className="text-blue-600 hover:text-blue-800"
          >
            Edit Profile →
          </Link>
        </div>
        
        <div className="bg-white p-6 rounded-lg shadow">
          <h2 className="text-xl font-semibold mb-2">Security</h2>
          <p className="text-gray-600 mb-4">
            Update password and 2FA settings
          </p>
          <Link
            to="/security"
            className="text-blue-600 hover:text-blue-800"
          >
            Security Settings →
          </Link>
        </div>
        
        <div className="bg-white p-6 rounded-lg shadow">
          <h2 className="text-xl font-semibold mb-2">Sessions</h2>
          <p className="text-gray-600 mb-4">
            Manage active sessions
          </p>
          <button className="text-blue-600 hover:text-blue-800">
            View Sessions →
          </button>
        </div>
      </div>
    </div>
  );
}
```

### Profile

```tsx
// src/pages/Profile.tsx
import { UserProfile } from '@vault/react';

export function Profile() {
  return (
    <div className="container mx-auto px-4 py-8">
      <h1 className="text-2xl font-bold mb-8">Your Profile</h1>
      <div className="max-w-2xl">
        <UserProfile
          onUpdate={(user) => {
            console.log('Profile updated:', user);
          }}
        />
      </div>
    </div>
  );
}
```

## Custom Hooks

### useAuthCheck

```tsx
// src/hooks/useAuthCheck.ts
import { useAuth } from '@vault/react';
import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

export function useAuthCheck(requireAuth: boolean = true) {
  const { isLoaded, isSignedIn } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (!isLoaded) return;

    if (requireAuth && !isSignedIn) {
      navigate('/sign-in');
    }

    if (!requireAuth && isSignedIn) {
      navigate('/dashboard');
    }
  }, [isLoaded, isSignedIn, requireAuth, navigate]);

  return { isLoaded, isSignedIn };
}
```

## Global Styles

```css
/* src/styles/globals.css */
@tailwind base;
@tailwind components;
@tailwind utilities;

:root {
  --color-primary: #2563eb;
}

body {
  font-family: system-ui, -apple-system, sans-serif;
}
```

## TypeScript Types

```ts
// src/types/env.d.ts
/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_VAULT_API_URL: string;
  readonly VITE_VAULT_TENANT_ID: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
```

## Build Configuration

### Vite Config

```ts
// vite.config.ts
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
  },
  build: {
    outDir: 'dist',
  },
});
```

## Testing

### Setup Tests

```tsx
// src/test/setup.ts
import '@testing-library/jest-dom';
```

### Component Test

```tsx
// src/components/Header.test.tsx
import { render, screen } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import { VaultProvider } from '@vault/react';
import { Header } from './Header';

const wrapper = ({ children }: { children: React.ReactNode }) => (
  <BrowserRouter>
    <VaultProvider config={{ apiUrl: 'https://test', tenantId: 'test' }}>
      {children}
    </VaultProvider>
  </BrowserRouter>
);

test('renders header', () => {
  render(<Header />, { wrapper });
  
  expect(screen.getByText('MyApp')).toBeInTheDocument();
});
```

## Deployment

### Build

```bash
npm run build
```

### Preview

```bash
npm run preview
```

## Best Practices

1. **Use environment variables** for configuration
2. **Create reusable components** for common patterns
3. **Implement proper loading states**
4. **Use route protection** for authenticated pages
5. **Handle errors gracefully**

## See Also

- [Vite Documentation](https://vitejs.dev/)
- [React Router](https://reactrouter.com/)
- [Components](../components/README.md) - Component documentation
