/**
 * LoginForm Component
 * 
 * Pre-built login form with email/password, social login, and magic link support.
 */

import React, { useState, useCallback } from 'react';
import { useVaultAuth, useSignIn } from '@vault/react';
import type { LoginFormProps, LoginCredentials, AuthError } from '../types';
import { Button, Input, Alert, SocialButtons } from './ui';
import { classNames, getThemeClass } from '../styles';

type LoginView = 'password' | 'magic-link';

/**
 * Pre-built login form component
 * 
 * @example
 * ```tsx
 * <LoginForm 
 *   onSuccess={(user) => console.log('Logged in:', user)}
 *   onError={(error) => console.error('Login failed:', error)}
 *   socialProviders={['google', 'github']}
 *   enableMagicLink
 * />
 * ```
 */
export const LoginForm: React.FC<LoginFormProps> = ({
  onSuccess,
  onError,
  redirectUrl,
  showSignupLink = true,
  showForgotPassword = true,
  socialProviders = [],
  enableMagicLink = false,
  theme = 'light',
  className,
  style,
}) => {
  const { signIn, signInWithMagicLink, signInWithOAuth } = useVaultAuth();
  const { isLoading: signInLoading, error: signInError, resetError } = useSignIn();
  
  const [view, setView] = useState<LoginView>('password');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [magicLinkSent, setMagicLinkSent] = useState(false);
  const [localError, setLocalError] = useState<AuthError | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});

  const isLoading = signInLoading;
  const error = localError || (signInError ? {
    code: 'auth_error',
    message: signInError.message || 'Authentication failed',
  } : null);

  const validateForm = useCallback((): boolean => {
    const errors: Record<string, string> = {};
    
    if (!email.trim()) {
      errors.email = 'Email is required';
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      errors.email = 'Please enter a valid email';
    }

    if (view === 'password' && !password) {
      errors.password = 'Password is required';
    }

    setFieldErrors(errors);
    return Object.keys(errors).length === 0;
  }, [email, password, view]);

  const handleSubmit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    setLocalError(null);
    resetError();

    if (!validateForm()) return;

    try {
      if (view === 'magic-link') {
        await signInWithMagicLink({ 
          email, 
          redirectUrl 
        });
        setMagicLinkSent(true);
      } else {
        const credentials: LoginCredentials = { email, password };
        await signIn(credentials);
        onSuccess?.(null as any); // User will be available via context
      }
    } catch (err) {
      const authError: AuthError = {
        code: 'login_failed',
        message: err instanceof Error ? err.message : 'Login failed. Please try again.',
      };
      setLocalError(authError);
      onError?.(authError);
    }
  }, [email, password, view, redirectUrl, validateForm, signIn, signInWithMagicLink, onSuccess, onError, resetError]);

  const handleSocialLogin = useCallback(async (provider: 'google' | 'github' | 'microsoft') => {
    try {
      setLocalError(null);
      await signInWithOAuth({ 
        provider, 
        redirectUrl 
      });
    } catch (err) {
      const authError: AuthError = {
        code: 'social_login_failed',
        message: err instanceof Error ? err.message : 'Social login failed. Please try again.',
      };
      setLocalError(authError);
      onError?.(authError);
    }
  }, [redirectUrl, signInWithOAuth, onError]);

  const themeClass = getThemeClass(theme);

  if (magicLinkSent) {
    return (
      <div className={classNames('vault-login-form', themeClass, className)} style={style}>
        <Alert variant="success" title="Check your email">
          We've sent a magic link to <strong>{email}</strong>. Click the link to sign in.
        </Alert>
        <Button 
          variant="ghost" 
          fullWidth 
          onClick={() => {
            setMagicLinkSent(false);
            setEmail('');
          }}
          className="vault-mt-4"
        >
          Back to sign in
        </Button>
      </div>
    );
  }

  return (
    <div className={classNames('vault-login-form', themeClass, className)} style={style}>
      <div className="vault-login-header">
        <h2 className="vault-login-title">Sign in to your account</h2>
        <p className="vault-login-subtitle">
          Welcome back! Please enter your details.
        </p>
      </div>

      {error && (
        <Alert variant="error" className="vault-mb-4">
          {error.message}
        </Alert>
      )}

      {socialProviders.length > 0 && (
        <>
          <SocialButtons
            providers={socialProviders}
            isLoading={isLoading}
            onProviderClick={handleSocialLogin}
          />
          <div className="vault-divider">
            <span>or</span>
          </div>
        </>
      )}

      <form onSubmit={handleSubmit} className="vault-login-form-fields">
        <Input
          type="email"
          label="Email"
          placeholder="Enter your email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          error={fieldErrors.email}
          disabled={isLoading}
          required
          autoComplete="email"
        />

        {view === 'password' && (
          <Input
            type="password"
            label="Password"
            placeholder="Enter your password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            error={fieldErrors.password}
            disabled={isLoading}
            required
            autoComplete="current-password"
          />
        )}

        {view === 'password' && showForgotPassword && (
          <div className="vault-forgot-password">
            <a href="#forgot-password" className="vault-link">
              Forgot password?
            </a>
          </div>
        )}

        <Button
          type="submit"
          variant="primary"
          fullWidth
          isLoading={isLoading}
          className="vault-mt-2"
        >
          {view === 'magic-link' ? 'Send magic link' : 'Sign in'}
        </Button>

        {enableMagicLink && (
          <div className="vault-login-toggle">
            {view === 'password' ? (
              <button
                type="button"
                className="vault-link vault-link-text"
                onClick={() => setView('magic-link')}
              >
                Sign in with magic link instead
              </button>
            ) : (
              <button
                type="button"
                className="vault-link vault-link-text"
                onClick={() => setView('password')}
              >
                Sign in with password instead
              </button>
            )}
          </div>
        )}
      </form>

      {showSignupLink && (
        <div className="vault-login-footer">
          <p>
            Don't have an account?{' '}
            <a href="#signup" className="vault-link">
              Sign up
            </a>
          </p>
        </div>
      )}
    </div>
  );
};
