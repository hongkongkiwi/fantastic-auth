/**
 * PasswordResetForm Component
 * 
 * Pre-built password reset form for requesting and completing password resets.
 */

import React, { useState, useCallback } from 'react';
import { usePasswordReset } from '../hooks/useAuth';
import type { PasswordResetFormProps, AuthError } from '../types';
import { Button, Input, Alert } from './ui';
import { classNames, getThemeClass } from '../styles';

type ResetView = 'request' | 'success' | 'complete';

/**
 * Pre-built password reset form component
 * 
 * @example
 * ```tsx
 * // Request password reset
 * <PasswordResetForm onSuccess={() => console.log('Email sent')} />
 * 
 * // Complete password reset (with token from URL)
 * <PasswordResetForm token={resetToken} onSuccess={() => console.log('Password reset')} />
 * ```
 */
export const PasswordResetForm: React.FC<PasswordResetFormProps> = ({
  token,
  onSuccess,
  onError,
  redirectUrl,
  theme = 'light',
  className,
  style,
}) => {
  const { sendResetEmail, resetPassword, isLoading, error: hookError, clearError } = usePasswordReset();
  
  const [view, setView] = useState<ResetView>(token ? 'complete' : 'request');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [localError, setLocalError] = useState<AuthError | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});

  const error = localError || (hookError ? {
    code: hookError.code || 'reset_error',
    message: hookError.message,
  } : null);

  const validateRequestForm = useCallback((): boolean => {
    const errors: Record<string, string> = {};

    if (!email.trim()) {
      errors.email = 'Email is required';
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      errors.email = 'Please enter a valid email';
    }

    setFieldErrors(errors);
    return Object.keys(errors).length === 0;
  }, [email]);

  const validateResetForm = useCallback((): boolean => {
    const errors: Record<string, string> = {};

    if (!password) {
      errors.password = 'Password is required';
    } else if (password.length < 8) {
      errors.password = 'Password must be at least 8 characters';
    }

    if (password !== confirmPassword) {
      errors.confirmPassword = 'Passwords do not match';
    }

    setFieldErrors(errors);
    return Object.keys(errors).length === 0;
  }, [password, confirmPassword]);

  const handleRequestSubmit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    setLocalError(null);
    clearError();

    if (!validateRequestForm()) return;

    try {
      await sendResetEmail(email);
      setView('success');
      onSuccess?.();
    } catch (err) {
      const authError: AuthError = {
        code: 'request_failed',
        message: err instanceof Error ? err.message : 'Failed to send reset email. Please try again.',
      };
      setLocalError(authError);
      onError?.(authError);
    }
  }, [email, validateRequestForm, sendResetEmail, onSuccess, onError, clearError]);

  const handleResetSubmit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    setLocalError(null);
    clearError();

    if (!token) {
      setLocalError({
        code: 'invalid_token',
        message: 'Invalid or missing reset token. Please request a new password reset.',
      });
      return;
    }

    if (!validateResetForm()) return;

    try {
      await resetPassword(token, password);
      onSuccess?.();
      
      if (redirectUrl) {
        window.location.href = redirectUrl;
      }
    } catch (err) {
      const authError: AuthError = {
        code: 'reset_failed',
        message: err instanceof Error ? err.message : 'Failed to reset password. Please try again.',
      };
      setLocalError(authError);
      onError?.(authError);
    }
  }, [token, password, validateResetForm, resetPassword, onSuccess, onError, clearError, redirectUrl]);

  const themeClass = getThemeClass(theme);

  // Success view after requesting reset
  if (view === 'success') {
    return (
      <div className={classNames('vault-reset-form', themeClass, className)} style={style}>
        <Alert variant="success" title="Check your email">
          We've sent password reset instructions to <strong>{email}</strong>. 
          Please check your email and follow the link to reset your password.
        </Alert>
        <Button 
          variant="ghost" 
          fullWidth 
          onClick={() => {
            setView('request');
            setEmail('');
          }}
          className="vault-mt-4"
        >
          Back to reset password
        </Button>
      </div>
    );
  }

  // Complete password reset view
  if (view === 'complete') {
    return (
      <div className={classNames('vault-reset-form', themeClass, className)} style={style}>
        <div className="vault-reset-header">
          <h2 className="vault-reset-title">Reset your password</h2>
          <p className="vault-reset-subtitle">
            Enter your new password below.
          </p>
        </div>

        {error && (
          <Alert variant="error" className="vault-mb-4">
            {error.message}
          </Alert>
        )}

        <form onSubmit={handleResetSubmit} className="vault-reset-form-fields">
          <Input
            type="password"
            label="New password"
            placeholder="Enter new password"
            value={password}
            onChange={(e) => {
              setPassword(e.target.value);
              if (fieldErrors.password) {
                setFieldErrors(prev => ({ ...prev, password: '' }));
              }
            }}
            error={fieldErrors.password}
            disabled={isLoading}
            required
            autoComplete="new-password"
          />

          <Input
            type="password"
            label="Confirm new password"
            placeholder="Confirm new password"
            value={confirmPassword}
            onChange={(e) => {
              setConfirmPassword(e.target.value);
              if (fieldErrors.confirmPassword) {
                setFieldErrors(prev => ({ ...prev, confirmPassword: '' }));
              }
            }}
            error={fieldErrors.confirmPassword}
            disabled={isLoading}
            required
            autoComplete="new-password"
          />

          <Button
            type="submit"
            variant="primary"
            fullWidth
            isLoading={isLoading}
            className="vault-mt-2"
          >
            Reset password
          </Button>
        </form>
      </div>
    );
  }

  // Request password reset view (default)
  return (
    <div className={classNames('vault-reset-form', themeClass, className)} style={style}>
      <div className="vault-reset-header">
        <h2 className="vault-reset-title">Reset your password</h2>
        <p className="vault-reset-subtitle">
          Enter your email address and we'll send you instructions to reset your password.
        </p>
      </div>

      {error && (
        <Alert variant="error" className="vault-mb-4">
          {error.message}
        </Alert>
      )}

      <form onSubmit={handleRequestSubmit} className="vault-reset-form-fields">
        <Input
          type="email"
          label="Email"
          placeholder="Enter your email"
          value={email}
          onChange={(e) => {
            setEmail(e.target.value);
            if (fieldErrors.email) {
              setFieldErrors(prev => ({ ...prev, email: '' }));
            }
          }}
          error={fieldErrors.email}
          disabled={isLoading}
          required
          autoComplete="email"
        />

        <Button
          type="submit"
          variant="primary"
          fullWidth
          isLoading={isLoading}
          className="vault-mt-2"
        >
          Send reset instructions
        </Button>
      </form>

      <div className="vault-reset-footer">
        <p>
          Remember your password?{' '}
          <a href="#login" className="vault-link">
            Sign in
          </a>
        </p>
      </div>
    </div>
  );
};
