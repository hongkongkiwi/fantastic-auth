/**
 * SignupForm Component
 * 
 * Pre-built signup form with email/password and social signup support.
 */

import React, { useState, useCallback } from 'react';
import { useVaultAuth, useSignUp } from '@vault/react';
import type { SignupFormProps, SignupData, AuthError } from '../types';
import { Button, Input, Alert, SocialButtons } from './ui';
import { classNames, getThemeClass } from '../styles';

/**
 * Pre-built signup form component
 * 
 * @example
 * ```tsx
 * <SignupForm 
 *   onSuccess={(user) => console.log('Signed up:', user)}
 *   onError={(error) => console.error('Signup failed:', error)}
 *   fields={['name', 'phone']}
 *   requireEmailVerification
 * />
 * ```
 */
export const SignupForm: React.FC<SignupFormProps> = ({
  onSuccess,
  onError,
  requireEmailVerification = false,
  allowedDomains = [],
  fields = [],
  termsUrl,
  privacyUrl,
  socialProviders = [],
  theme = 'light',
  className,
  style,
}) => {
  const { signUp, signInWithOAuth } = useVaultAuth();
  const { isLoading: signUpLoading, error: signUpError, resetError } = useSignUp();

  const [formData, setFormData] = useState({
    email: '',
    password: '',
    confirmPassword: '',
    name: '',
    phone: '',
    organization: '',
    agreeToTerms: false,
  });
  const [verificationSent, setVerificationSent] = useState(false);
  const [localError, setLocalError] = useState<AuthError | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});

  const isLoading = signUpLoading;
  const error = localError || (signUpError ? {
    code: 'signup_error',
    message: signUpError.message || 'Signup failed',
  } : null);

  const validateForm = useCallback((): boolean => {
    const errors: Record<string, string> = {};

    // Email validation
    if (!formData.email.trim()) {
      errors.email = 'Email is required';
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) {
      errors.email = 'Please enter a valid email';
    } else if (allowedDomains.length > 0) {
      const domain = formData.email.split('@')[1]?.toLowerCase();
      if (!allowedDomains.includes(domain)) {
        errors.email = `Email must be from: ${allowedDomains.join(', ')}`;
      }
    }

    // Password validation
    if (!formData.password) {
      errors.password = 'Password is required';
    } else if (formData.password.length < 8) {
      errors.password = 'Password must be at least 8 characters';
    }

    // Confirm password
    if (formData.password !== formData.confirmPassword) {
      errors.confirmPassword = 'Passwords do not match';
    }

    // Name validation (if required)
    if (fields.includes('name') && !formData.name.trim()) {
      errors.name = 'Name is required';
    }

    // Terms agreement
    if ((termsUrl || privacyUrl) && !formData.agreeToTerms) {
      errors.agreeToTerms = 'You must agree to the terms';
    }

    setFieldErrors(errors);
    return Object.keys(errors).length === 0;
  }, [formData, allowedDomains, fields, termsUrl, privacyUrl]);

  const handleChange = useCallback((field: string, value: string | boolean) => {
    setFormData(prev => ({ ...prev, [field]: value }));
    // Clear field error when user starts typing
    if (fieldErrors[field]) {
      setFieldErrors(prev => ({ ...prev, [field]: '' }));
    }
  }, [fieldErrors]);

  const handleSubmit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    setLocalError(null);
    resetError();

    if (!validateForm()) return;

    try {
      const signupData: SignupData = {
        email: formData.email,
        password: formData.password,
        name: fields.includes('name') ? formData.name : undefined,
        phone: fields.includes('phone') ? formData.phone : undefined,
        organization: fields.includes('organization') ? formData.organization : undefined,
      };

      await signUp(signupData);

      if (requireEmailVerification) {
        setVerificationSent(true);
      } else {
        onSuccess?.(null as any);
      }
    } catch (err) {
      const authError: AuthError = {
        code: 'signup_failed',
        message: err instanceof Error ? err.message : 'Signup failed. Please try again.',
      };
      setLocalError(authError);
      onError?.(authError);
    }
  }, [formData, fields, requireEmailVerification, validateForm, signUp, onSuccess, onError, resetError]);

  const handleSocialSignup = useCallback(async (provider: 'google' | 'github' | 'microsoft') => {
    try {
      setLocalError(null);
      await signInWithOAuth({ provider });
    } catch (err) {
      const authError: AuthError = {
        code: 'social_signup_failed',
        message: err instanceof Error ? err.message : 'Social signup failed. Please try again.',
      };
      setLocalError(authError);
      onError?.(authError);
    }
  }, [signInWithOAuth, onError]);

  const themeClass = getThemeClass(theme);

  if (verificationSent) {
    return (
      <div className={classNames('vault-signup-form', themeClass, className)} style={style}>
        <Alert variant="success" title="Verify your email">
          We've sent a verification link to <strong>{formData.email}</strong>. 
          Please check your email and click the link to complete your registration.
        </Alert>
      </div>
    );
  }

  return (
    <div className={classNames('vault-signup-form', themeClass, className)} style={style}>
      <div className="vault-signup-header">
        <h2 className="vault-signup-title">Create an account</h2>
        <p className="vault-signup-subtitle">
          Get started with your free account today.
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
            onProviderClick={handleSocialSignup}
          />
          <div className="vault-divider">
            <span>or</span>
          </div>
        </>
      )}

      <form onSubmit={handleSubmit} className="vault-signup-form-fields">
        {fields.includes('name') && (
          <Input
            type="text"
            label="Full name"
            placeholder="Enter your full name"
            value={formData.name}
            onChange={(e) => handleChange('name', e.target.value)}
            error={fieldErrors.name}
            disabled={isLoading}
            required
            autoComplete="name"
          />
        )}

        <Input
          type="email"
          label="Email"
          placeholder="Enter your email"
          value={formData.email}
          onChange={(e) => handleChange('email', e.target.value)}
          error={fieldErrors.email}
          disabled={isLoading}
          required
          autoComplete="email"
        />

        {fields.includes('phone') && (
          <Input
            type="tel"
            label="Phone number"
            placeholder="Enter your phone number"
            value={formData.phone}
            onChange={(e) => handleChange('phone', e.target.value)}
            disabled={isLoading}
            autoComplete="tel"
          />
        )}

        {fields.includes('organization') && (
          <Input
            type="text"
            label="Organization"
            placeholder="Enter your organization"
            value={formData.organization}
            onChange={(e) => handleChange('organization', e.target.value)}
            disabled={isLoading}
            autoComplete="organization"
          />
        )}

        <Input
          type="password"
          label="Password"
          placeholder="Create a password"
          value={formData.password}
          onChange={(e) => handleChange('password', e.target.value)}
          error={fieldErrors.password}
          disabled={isLoading}
          required
          autoComplete="new-password"
        />

        <Input
          type="password"
          label="Confirm password"
          placeholder="Confirm your password"
          value={formData.confirmPassword}
          onChange={(e) => handleChange('confirmPassword', e.target.value)}
          error={fieldErrors.confirmPassword}
          disabled={isLoading}
          required
          autoComplete="new-password"
        />

        {(termsUrl || privacyUrl) && (
          <div className={classNames('vault-checkbox-wrapper', fieldErrors.agreeToTerms && 'vault-checkbox-error')}>
            <label className="vault-checkbox-label">
              <input
                type="checkbox"
                checked={formData.agreeToTerms}
                onChange={(e) => handleChange('agreeToTerms', e.target.checked)}
                disabled={isLoading}
                className="vault-checkbox"
              />
              <span className="vault-checkbox-text">
                I agree to the{' '}
                {termsUrl ? (
                  <a href={termsUrl} target="_blank" rel="noopener noreferrer" className="vault-link">
                    Terms of Service
                  </a>
                ) : 'Terms of Service'}
                {termsUrl && privacyUrl && ' and '}
                {privacyUrl ? (
                  <a href={privacyUrl} target="_blank" rel="noopener noreferrer" className="vault-link">
                    Privacy Policy
                  </a>
                ) : 'Privacy Policy'}
              </span>
            </label>
            {fieldErrors.agreeToTerms && (
              <span className="vault-checkbox-error-text" role="alert">
                {fieldErrors.agreeToTerms}
              </span>
            )}
          </div>
        )}

        <Button
          type="submit"
          variant="primary"
          fullWidth
          isLoading={isLoading}
          className="vault-mt-2"
        >
          Create account
        </Button>
      </form>

      <div className="vault-signup-footer">
        <p>
          Already have an account?{' '}
          <a href="#login" className="vault-link">
            Sign in
          </a>
        </p>
      </div>
    </div>
  );
};
