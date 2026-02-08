/**
 * SignUp Component
 *
 * Pre-built sign-up form with email/password and OAuth options.
 * Uses the Clerk-style theming system.
 *
 * @example
 * ```tsx
 * <SignUp
 *   redirectUrl="/onboarding"
 *   oauthProviders={['google', 'github']}
 *   requireName={true}
 *   appearance={{
 *     baseTheme: 'dark',
 *     variables: { colorPrimary: '#ff0000' }
 *   }}
 * />
 * ```
 */

import React, { useState, useCallback } from 'react';
import { useSignUp } from '../hooks/useSignUp';
import { SignUpProps, ApiError } from '../types';
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
  Divider,
  SocialButton,
  SocialButtons,
  Alert,
} from './ui';

export type { SignUpProps };

// ============================================================================
// Main Component
// ============================================================================

export function SignUp({
  redirectUrl,
  onSignUp,
  onError,
  oauthProviders = [],
  requireName = false,
  appearance,
  className,
}: SignUpProps) {
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
    <SignUpContent
      redirectUrl={redirectUrl}
      onSignUp={onSignUp}
      onError={onError}
      oauthProviders={oauthProviders}
      requireName={requireName}
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

function SignUpContent({
  redirectUrl,
  onSignUp,
  onError,
  oauthProviders,
  requireName,
  className,
}: SignUpProps) {
  const { signUp, signUpWithOAuth, isLoading, error, resetError } = useSignUp();
  const { getLayoutOption, cssVariables } = useTheme();

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [name, setName] = useState('');
  const [localError, setLocalError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const socialButtonsPlacement = getLayoutOption('socialButtonsPlacement');
  const socialButtonsVariant = getLayoutOption('socialButtonsVariant');

  const handleSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      resetError();
      setLocalError(null);

      // Validation
      if (password !== confirmPassword) {
        setLocalError('Passwords do not match');
        return;
      }

      if (password.length < 12) {
        setLocalError('Password must be at least 12 characters');
        return;
      }

      try {
        await signUp({
          email,
          password,
          name: name || undefined,
        });
        setSuccess(true);
        onSignUp?.();
        if (redirectUrl) {
          window.location.href = redirectUrl;
        }
      } catch (err: any) {
        const errorMessage = err.message || 'Failed to create account';
        setLocalError(errorMessage);
        onError?.(err as ApiError);
      }
    },
    [email, password, confirmPassword, name, requireName, signUp, redirectUrl, onSignUp, onError, resetError]
  );

  const handleOAuth = useCallback(
    async (provider: 'google' | 'github' | 'microsoft') => {
      resetError();
      setLocalError(null);
      try {
        await signUpWithOAuth({ provider, redirectUrl });
      } catch (err: any) {
        setLocalError(err.message || 'Failed to sign up');
        onError?.(err as ApiError);
      }
    },
    [signUpWithOAuth, redirectUrl, onError, resetError]
  );

  const displayError = localError || error?.message;

  // Success state
  if (success) {
    return (
      <Card className={className} centered>
        <CardHeader
          title="Account created!"
          subtitle="Welcome! Your account has been successfully created."
        />
        {redirectUrl && (
          <CardContent>
            <p
              style={{
                textAlign: 'center',
                color: cssVariables['--vault-color-text-secondary'],
                fontFamily: cssVariables['--vault-font-family'],
              }}
            >
              Redirecting you...
            </p>
          </CardContent>
        )}
      </Card>
    );
  }

  const SocialButtonsSection = oauthProviders && oauthProviders.length > 0 && (
    <SocialButtons
      layout={socialButtonsVariant === 'iconButton' ? 'horizontal' : 'vertical'}
    >
      {oauthProviders?.map((provider) => (
        <SocialButton
          key={provider}
          provider={provider}
          variant={socialButtonsVariant === 'iconButton' ? 'icon' : 'block'}
          onClick={() => handleOAuth(provider)}
          disabled={isLoading}
        />
      ))}
    </SocialButtons>
  );

  return (
    <Card className={className} centered>
      <CardHeader title="Create Account" />

      <CardContent>
        {displayError && (
          <Alert variant="error" style={{ marginBottom: '1rem' }}>
            {displayError}
          </Alert>
        )}

        {socialButtonsPlacement === 'top' && SocialButtonsSection}
        {socialButtonsPlacement === 'top' && (oauthProviders || []).length > 0 && (
          <Divider text="or" />
        )}

        <form onSubmit={handleSubmit}>
          {(requireName || name) && (
            <Input
              label="Full Name"
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required={requireName}
              autoComplete="name"
              disabled={isLoading}
              placeholder="John Doe"
            />
          )}

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

          <Input
            label="Password"
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
            Create Account
          </Button>
        </form>

        {socialButtonsPlacement === 'bottom' && (oauthProviders || []).length > 0 && (
          <Divider text="or" />
        )}
        {socialButtonsPlacement === 'bottom' && SocialButtonsSection}
      </CardContent>

      <CardFooter>
        <span
          style={{
            fontSize: '0.875rem',
            color: cssVariables['--vault-color-text-secondary'],
            fontFamily: cssVariables['--vault-font-family'],
          }}
        >
          Already have an account?{' '}
          <a
            href="/sign-in"
            style={{
              color: cssVariables['--vault-color-primary'],
              textDecoration: 'none',
              fontWeight: 500,
            }}
          >
            Sign in
          </a>
        </span>
      </CardFooter>
    </Card>
  );
}
