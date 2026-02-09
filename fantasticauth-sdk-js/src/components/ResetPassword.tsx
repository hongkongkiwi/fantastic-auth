/**
 * ResetPassword Component
 *
 * Password reset form component.
 * Uses the Clerk-style theming system.
 *
 * @example
 * ```tsx
 * // With token from URL
 * const token = new URLSearchParams(window.location.search).get('token');
 * <ResetPassword
 *   token={token}
 *   onSuccess={() => navigate('/dashboard')}
 *   appearance={{
 *     baseTheme: 'dark',
 *     variables: { colorPrimary: '#ff0000' }
 *   }}
 * />
 *
 * // Request reset email
 * <ResetPassword requestMode />
 * ```
 */

import React, { useState, useCallback } from 'react';
import { useVault } from '../context/VaultContext';
import { ResetPasswordProps, ApiError } from '../types';
import {
  ThemeProvider,
  useTheme,
} from '../theme';
import {
  Card,
  CardHeader,
  CardContent,
  CardFooter,
  Button,
  Input,
  Alert,
} from './ui';

export type { ResetPasswordProps };

// ============================================================================
// Main Component
// ============================================================================

export function ResetPassword({
  token,
  onSuccess,
  onError,
  redirectUrl,
  appearance,
  className,
}: ResetPasswordProps) {
  // Determine if we need to wrap with ThemeProvider
  const [isThemed] = useState(() => {
    try {
      useTheme();
      return true;
    } catch {
      return false;
    }
  });

  const content = (
    <ResetPasswordContent
      token={token}
      onSuccess={onSuccess}
      onError={onError}
      redirectUrl={redirectUrl}
      appearance={appearance}
      className={className}
    />
  );

  // Wrap with ThemeProvider if not already themed
  if (!isThemed && appearance) {
    return (
      <ThemeProvider appearance={appearance}>
        {content}
      </ThemeProvider>
    );
  }

  return content;
}

// ============================================================================
// Internal Content Component
// ============================================================================

function ResetPasswordContent({
  token,
  onSuccess,
  onError,
  redirectUrl,
  className,
}: ResetPasswordProps) {
  const { sendForgotPassword, resetPassword } = useVault();
  const { cssVariables } = useTheme();

  const [mode] = useState<'request' | 'reset'>(token ? 'reset' : 'request');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);
  const [emailSent, setEmailSent] = useState(false);

  const handleRequestReset = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setError(null);

    try {
      await sendForgotPassword({ email, redirectUrl });
      setEmailSent(true);
    } catch (err: any) {
      const errorMessage = err.message || 'Failed to send reset email';
      setError(errorMessage);
      onError?.(err as ApiError);
    } finally {
      setIsLoading(false);
    }
  }, [email, redirectUrl, sendForgotPassword, onError]);

  const handleResetPassword = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    // Validation
    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    if (password.length < 12) {
      setError('Password must be at least 12 characters');
      return;
    }

    if (!token) {
      setError('Invalid reset token');
      return;
    }

    setIsLoading(true);

    try {
      await resetPassword({ token, password });
      setSuccess(true);
      onSuccess?.();

      if (redirectUrl) {
        setTimeout(() => {
          window.location.href = redirectUrl;
        }, 2000);
      }
    } catch (err: any) {
      const errorMessage = err.message || 'Failed to reset password';
      setError(errorMessage);
      onError?.(err as ApiError);
    } finally {
      setIsLoading(false);
    }
  }, [password, confirmPassword, token, resetPassword, onSuccess, onError, redirectUrl]);

  // Email sent success state
  if (emailSent) {
    return (
      <Card className={className} centered>
        <CardHeader
          title="Check your email"
          subtitle={`We've sent a password reset link to ${email}. Please check your inbox and follow the instructions.`}
        />
        <CardContent>
          <SuccessIcon />
          <Button
            variant="ghost"
            onClick={() => {
              setEmailSent(false);
              setEmail('');
            }}
          >
            Didn't receive it? Try again
          </Button>
        </CardContent>
      </Card>
    );
  }

  // Password reset success state
  if (success) {
    return (
      <Card className={className} centered>
        <CardHeader
          title="Password reset successful!"
          subtitle={`Your password has been successfully reset.${redirectUrl ? ' Redirecting you...' : ''}`}
        />
        <CardContent>
          <SuccessIcon />
        </CardContent>
      </Card>
    );
  }

  // Request reset form
  if (mode === 'request') {
    return (
      <Card className={className} centered>
        <CardHeader
          title="Reset your password"
          subtitle="Enter your email address and we'll send you a link to reset your password."
        />

        <CardContent>
          {error && (
            <Alert variant="error" style={{ marginBottom: '1rem' }}>
              {error}
            </Alert>
          )}

          <form onSubmit={handleRequestReset}>
            <Input
              label="Email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              autoComplete="email"
              disabled={isLoading}
              placeholder="you@example.com"
            />

            <Button type="submit" isLoading={isLoading} style={{ marginTop: '0.5rem' }}>
              Send reset link
            </Button>
          </form>
        </CardContent>

        <CardFooter>
          <a
            href="/sign-in"
            style={{
              fontSize: '0.875rem',
              color: cssVariables['--vault-color-primary'],
              textDecoration: 'none',
              fontFamily: cssVariables['--vault-font-family'],
            }}
          >
            Back to sign in
          </a>
        </CardFooter>
      </Card>
    );
  }

  // Reset password form
  return (
    <Card className={className} centered>
      <CardHeader
        title="Create new password"
        subtitle="Enter your new password below."
      />

      <CardContent>
        {error && (
          <Alert variant="error" style={{ marginBottom: '1rem' }}>
            {error}
          </Alert>
        )}

        <form onSubmit={handleResetPassword}>
          <Input
            label="New Password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            minLength={12}
            autoComplete="new-password"
            disabled={isLoading}
            placeholder="Min 12 characters"
            helperText="Must be at least 12 characters"
          />

          <Input
            label="Confirm Password"
            type="password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            required
            autoComplete="new-password"
            disabled={isLoading}
            placeholder="Re-enter your password"
          />

          <Button type="submit" isLoading={isLoading} style={{ marginTop: '0.5rem' }}>
            Reset password
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}

// Success Icon Component
function SuccessIcon() {
  const { cssVariables } = useTheme();

  return (
    <div style={{ textAlign: 'center', marginBottom: '1rem' }}>
      <svg
        width="48"
        height="48"
        viewBox="0 0 24 24"
        fill="none"
        stroke={cssVariables['--vault-color-success']}
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <circle cx="12" cy="12" r="10" />
        <path d="m9 12 2 2 4-4" />
      </svg>
    </div>
  );
}
