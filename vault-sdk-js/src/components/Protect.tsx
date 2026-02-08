/**
 * Protect Component
 * 
 * Route protection component that conditionally renders children based on authentication state.
 * 
 * @example
 * ```tsx
 * <Protect>
 *   <Dashboard />
 * </Protect>
 * 
 * // With fallback
 * <Protect fallback={<LoginPrompt />}>
 *   <Dashboard />
 * </Protect>
 * 
 * // With role check
 * <Protect role="admin">
 *   <AdminPanel />
 * </Protect>
 * ```
 */

import React from 'react';
import { useAuth } from '../hooks/useAuth';
import { useOrganization } from '../hooks/useOrganization';
import { ProtectProps } from '../types';

export type { ProtectProps };

export function Protect({
  children,
  fallback,
  role,
  permission,
  loading,
}: ProtectProps) {
  const { isLoaded, isSignedIn, user } = useAuth();
  const { organization } = useOrganization();

  // Show loading state
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

  // Not signed in
  if (!isSignedIn || !user) {
    if (fallback) {
      return <>{fallback}</>;
    }
    return (
      <div style={styles.unauthorized}>
        <h2 style={styles.title}>Sign in required</h2>
        <p style={styles.message}>
          You need to be signed in to access this page.
        </p>
        <a href="/sign-in" style={styles.link}>
          Sign In
        </a>
      </div>
    );
  }

  // Check role requirement
  if (role) {
    const userRole = organization?.role;
    if (userRole !== role && userRole !== 'owner') {
      return (
        <div style={styles.unauthorized}>
          <h2 style={styles.title}>Access denied</h2>
          <p style={styles.message}>
            You don't have the required role to access this page.
          </p>
          <a href="/" style={styles.link}>
            Go Home
          </a>
        </div>
      );
    }
  }

  // Check permission requirement
  if (permission) {
    // This would check user permissions
    // For now, we'll just pass through
  }

  // All checks passed, render children
  return <>{children}</>;
}

/**
 * SignedIn Component
 * 
 * Only renders children when user is signed in.
 * 
 * @example
 * ```tsx
 * <SignedIn>
 *   <UserNav />
 * </SignedIn>
 * ```
 */
export function SignedIn({ children }: { children: React.ReactNode }) {
  const { isSignedIn, isLoaded } = useAuth();
  
  if (!isLoaded || !isSignedIn) {
    return null;
  }
  
  return <>{children}</>;
}

/**
 * SignedOut Component
 * 
 * Only renders children when user is signed out.
 * 
 * @example
 * ```tsx
 * <SignedOut>
 *   <LoginButton />
 * </SignedOut>
 * ```
 */
export function SignedOut({ children }: { children: React.ReactNode }) {
  const { isSignedIn, isLoaded } = useAuth();
  
  if (!isLoaded || isSignedIn) {
    return null;
  }
  
  return <>{children}</>;
}

/**
 * RedirectToSignIn Component
 * 
 * Redirects to sign in page.
 * 
 * @example
 * ```tsx
 * <RedirectToSignIn redirectUrl="/dashboard" />
 * ```
 */
export function RedirectToSignIn({ redirectUrl }: { redirectUrl?: string }) {
  const { isLoaded, isSignedIn } = useAuth();

  React.useEffect(() => {
    if (isLoaded && !isSignedIn) {
      const url = redirectUrl 
        ? `/sign-in?redirect_url=${encodeURIComponent(redirectUrl)}`
        : '/sign-in';
      window.location.href = url;
    }
  }, [isLoaded, isSignedIn, redirectUrl]);

  return (
    <div style={styles.loading}>
      <div style={styles.spinner} />
      <span>Redirecting...</span>
    </div>
  );
}

/**
 * RedirectToSignUp Component
 * 
 * Redirects to sign up page.
 * 
 * @example
 * ```tsx
 * <RedirectToSignUp redirectUrl="/dashboard" />
 * ```
 */
export function RedirectToSignUp({ redirectUrl }: { redirectUrl?: string }) {
  const { isLoaded, isSignedIn } = useAuth();

  React.useEffect(() => {
    if (isLoaded && !isSignedIn) {
      const url = redirectUrl 
        ? `/sign-up?redirect_url=${encodeURIComponent(redirectUrl)}`
        : '/sign-up';
      window.location.href = url;
    }
  }, [isLoaded, isSignedIn, redirectUrl]);

  return (
    <div style={styles.loading}>
      <div style={styles.spinner} />
      <span>Redirecting...</span>
    </div>
  );
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
  unauthorized: {
    maxWidth: '400px',
    margin: '48px auto',
    padding: '32px',
    textAlign: 'center',
    backgroundColor: '#f9fafb',
    borderRadius: '8px',
    border: '1px solid #e5e7eb',
  },
  title: {
    fontSize: '20px',
    fontWeight: 600,
    margin: '0 0 8px',
    color: '#1f2937',
  },
  message: {
    fontSize: '14px',
    color: '#6b7280',
    margin: '0 0 20px',
  },
  link: {
    display: 'inline-block',
    padding: '10px 20px',
    fontSize: '14px',
    fontWeight: 500,
    color: '#fff',
    backgroundColor: '#0066cc',
    borderRadius: '6px',
    textDecoration: 'none',
  },
};
