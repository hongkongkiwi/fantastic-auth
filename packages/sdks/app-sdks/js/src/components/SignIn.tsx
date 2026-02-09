/**
 * SignIn Component
 *
 * Pre-built sign-in form with email/password, magic link, OAuth, and WebAuthn options.
 * Uses the Clerk-style theming system.
 *
 * @example
 * ```tsx
 * <SignIn
 *   redirectUrl="/dashboard"
 *   oauthProviders={['google', 'github']}
 *   showMagicLink={true}
 *   appearance={{
 *     baseTheme: 'dark',
 *     variables: { colorPrimary: '#ff0000' }
 *   }}
 * />
 * ```
 */

import React, { useState, useCallback } from 'react';
import { useSignIn } from '../hooks/useSignIn';
import { useWebAuthn } from '../hooks/useWebAuthn';
import { SignInProps, ApiError } from '../types';
import {
  ThemeProvider,
  useTheme,
} from '../theme';
import {
  Card,
  CardHeader,
  CardContent,
  Button,
  Input,
  Divider,
  SocialButton,
  SocialButtons,
  Alert,
} from './ui';

export type { SignInProps };

// ============================================================================
// Main Component
// ============================================================================

export function SignIn({
  redirectUrl,
  onSignIn,
  onError,
  showMagicLink = true,
  showForgotPassword = true,
  oauthProviders = [],
  showWebAuthn = false,
  appearance,
  className,
}: SignInProps) {
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
    <SignInContent
      redirectUrl={redirectUrl}
      onSignIn={onSignIn}
      onError={onError}
      showMagicLink={showMagicLink}
      showForgotPassword={showForgotPassword}
      oauthProviders={oauthProviders}
      showWebAuthn={showWebAuthn}
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

function SignInContent({
  redirectUrl,
  onSignIn,
  onError,
  showMagicLink,
  showForgotPassword,
  oauthProviders,
  showWebAuthn,
  className,
}: SignInProps) {
  const { signIn, signInWithMagicLink, signInWithOAuth, isLoading, error, resetError } = useSignIn();
  const { isSupported: isWebAuthnSupported, authenticate: authenticateWithWebAuthn } = useWebAuthn();
  const { getLayoutOption, cssVariables } = useTheme();

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [useMagicLink, setUseMagicLink] = useState(false);
  const [magicLinkSent, setMagicLinkSent] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);

  const socialButtonsPlacement = getLayoutOption('socialButtonsPlacement');
  const socialButtonsVariant = getLayoutOption('socialButtonsVariant');

  const handleSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      resetError();
      setLocalError(null);

      try {
        if (useMagicLink) {
          await signInWithMagicLink({ email, redirectUrl });
          setMagicLinkSent(true);
        } else {
          await signIn({ email, password });
          onSignIn?.();
          if (redirectUrl) {
            window.location.href = redirectUrl;
          }
        }
      } catch (err: any) {
        const errorMessage = err.message || 'Failed to sign in';
        setLocalError(errorMessage);
        onError?.(err as ApiError);
      }
    },
    [email, password, useMagicLink, signIn, signInWithMagicLink, redirectUrl, onSignIn, onError, resetError]
  );

  const handleOAuth = useCallback(
    async (provider: 'google' | 'github' | 'microsoft') => {
      resetError();
      setLocalError(null);
      try {
        await signInWithOAuth({ provider, redirectUrl });
      } catch (err: any) {
        setLocalError(err.message || 'Failed to sign in');
        onError?.(err as ApiError);
      }
    },
    [signInWithOAuth, redirectUrl, onError, resetError]
  );

  const handleWebAuthn = useCallback(async () => {
    resetError();
    setLocalError(null);
    try {
      await authenticateWithWebAuthn();
      onSignIn?.();
      if (redirectUrl) {
        window.location.href = redirectUrl;
      }
    } catch (err: any) {
      setLocalError(err.message || 'Passkey authentication failed');
      onError?.(err as ApiError);
    }
  }, [authenticateWithWebAuthn, redirectUrl, onSignIn, onError, resetError]);

  const handleForgotPassword = useCallback(() => {
    window.location.href = `/forgot-password?email=${encodeURIComponent(email)}`;
  }, [email]);

  const displayError = localError || error?.message;

  // Magic link sent state
  if (magicLinkSent) {
    return (
      <Card className={className} centered>
        <CardHeader
          title="Check your email"
          subtitle={`We've sent a magic link to ${email}`}
        />
        <CardContent>
          <p
            style={{
              textAlign: 'center',
              color: cssVariables['--vault-color-text-secondary'],
              fontFamily: cssVariables['--vault-font-family'],
            }}
          >
            Click the link in the email to sign in.
          </p>
          <Button
            variant="ghost"
            onClick={() => {
              setMagicLinkSent(false);
              setEmail('');
            }}
          >
            Back to sign in
          </Button>
        </CardContent>
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
      <CardHeader title="Sign In" />

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

          {!useMagicLink && (
            <div style={{ position: 'relative' }}>
              <Input
                label="Password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required={!useMagicLink}
                autoComplete="current-password"
                disabled={isLoading}
              />
              {showForgotPassword && (
                <button
                  type="button"
                  onClick={handleForgotPassword}
                  style={{
                    position: 'absolute',
                    right: 0,
                    top: 0,
                    fontSize: '0.75rem',
                    color: cssVariables['--vault-color-primary'],
                    background: 'none',
                    border: 'none',
                    cursor: 'pointer',
                    fontFamily: cssVariables['--vault-font-family'],
                  }}
                >
                  Forgot password?
                </button>
              )}
            </div>
          )}

          <Button type="submit" isLoading={isLoading} style={{ marginTop: '0.5rem' }}>
            {useMagicLink ? 'Send Magic Link' : 'Sign In'}
          </Button>
        </form>

        {showMagicLink && (
          <Button
            variant="ghost"
            onClick={() => {
              setUseMagicLink(!useMagicLink);
              resetError();
              setLocalError(null);
            }}
          >
            {useMagicLink ? 'Use password instead' : 'Use magic link instead'}
          </Button>
        )}

        {showWebAuthn && isWebAuthnSupported && (
          <>
            <Divider text="or" />
            <Button variant="secondary" onClick={handleWebAuthn} disabled={isLoading}>
              <span style={{ marginRight: '0.5rem' }}>🔐</span>
              Sign in with Passkey
            </Button>
          </>
        )}

        {socialButtonsPlacement === 'bottom' && (oauthProviders || []).length > 0 && (
          <Divider text="or" />
        )}
        {socialButtonsPlacement === 'bottom' && SocialButtonsSection}
      </CardContent>
    </Card>
  );
}
