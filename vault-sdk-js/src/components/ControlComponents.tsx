/**
 * Control Components
 * 
 * Utility components for conditional rendering based on auth state.
 * 
 * @example
 * ```tsx
 * <SignedIn>
 *   <UserButton />
 * </SignedIn>
 * 
 * <SignedOut>
 *   <SignInButton />
 * </SignedOut>
 * 
 * <RequireAuth fallback={<LoginPrompt />}>
 *   <ProtectedContent />
 * </RequireAuth>
 * ```
 */

import React from 'react';
import { useAuth } from '../hooks/useAuth';

export interface SignedInProps {
  children: React.ReactNode;
}

/**
 * Renders children only when user is signed in.
 */
export function SignedIn({ children }: SignedInProps) {
  const { isSignedIn, isLoaded } = useAuth();
  
  if (!isLoaded) {
    return null;
  }
  
  return isSignedIn ? <>{children}</> : null;
}

export interface SignedOutProps {
  children: React.ReactNode;
}

/**
 * Renders children only when user is signed out.
 */
export function SignedOut({ children }: SignedOutProps) {
  const { isSignedIn, isLoaded } = useAuth();
  
  if (!isLoaded) {
    return null;
  }
  
  return !isSignedIn ? <>{children}</> : null;
}

export interface RequireAuthProps {
  children: React.ReactNode;
  fallback?: React.ReactNode;
  loading?: React.ReactNode;
}

/**
 * Renders children only when user is signed in.
 * Shows fallback (or default message) when signed out.
 * Shows loading state while auth is loading.
 */
export function RequireAuth({ children, fallback, loading }: RequireAuthProps) {
  const { isSignedIn, isLoaded } = useAuth();
  
  if (!isLoaded) {
    if (loading) {
      return <>{loading}</>;
    }
    return (
      <div style={styles.loading}>
        <div style={styles.spinner} />
        <span>Loading...</span>
      </div>
    );
  }
  
  if (!isSignedIn) {
    if (fallback) {
      return <>{fallback}</>;
    }
    return (
      <div style={styles.unauthenticated}>
        <p>Please sign in to continue.</p>
        <a href="/sign-in" style={styles.link}>Sign In</a>
      </div>
    );
  }
  
  return <>{children}</>;
}

// Styles
const styles: Record<string, React.CSSProperties> = {
  loading: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '12px',
    padding: '48px',
    color: '#6b7280',
  },
  spinner: {
    width: '20px',
    height: '20px',
    border: '2px solid #e5e7eb',
    borderTopColor: '#0066cc',
    borderRadius: '50%',
    animation: 'spin 1s linear infinite',
  },
  unauthenticated: {
    padding: '48px',
    textAlign: 'center',
    color: '#6b7280',
  },
  link: {
    color: '#0066cc',
    textDecoration: 'none',
  },
};
