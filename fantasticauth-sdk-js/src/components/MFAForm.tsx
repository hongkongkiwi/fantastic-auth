/**
 * MFAForm Component
 *
 * Multi-factor authentication verification form.
 * Uses the Clerk-style theming system.
 *
 * @example
 * ```tsx
 * <MFAForm
 *   allowBackupCode={true}
 *   onVerify={() => navigate('/dashboard')}
 *   appearance={{
 *     baseTheme: 'dark',
 *     variables: { colorPrimary: '#ff0000' }
 *   }}
 * />
 *
 * // Inside a sign-in flow
 * function SignInPage() {
 *   const { authState } = useAuth();
 *
 *   if (authState.status === 'mfa_required') {
 *     return <MFAForm />;
 *   }
 *
 *   return <SignIn />;
 * }
 * ```
 */

import React, { useState, useRef, useEffect, useCallback } from 'react';
import { useMfaChallenge } from '../hooks/useMfa';
import { useVault } from '../context/VaultContext';
import { MFAFormProps, MfaMethod, ApiError } from '../types';
import {
  ThemeProvider,
  useTheme,
} from '../theme';
import {
  Card,
  CardHeader,
  CardContent,
  Button,
  Alert,
} from './ui';

export type { MFAFormProps };

// ============================================================================
// Main Component
// ============================================================================

export function MFAForm({
  challenge: propChallenge,
  onVerify,
  onError,
  allowBackupCode = true,
  appearance,
  className,
}: MFAFormProps) {
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
    <MFAFormContent
      challenge={propChallenge}
      onVerify={onVerify}
      onError={onError}
      allowBackupCode={allowBackupCode}
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

function MFAFormContent({
  challenge: propChallenge,
  onVerify,
  onError,
  allowBackupCode,
  className,
}: MFAFormProps) {
  const { challenge: contextChallenge, verify: contextVerify, isRequired } = useMfaChallenge();
  const { cssVariables } = useTheme();

  const challenge = propChallenge || contextChallenge;
  const verifyMfa = contextVerify;

  const [code, setCode] = useState(['', '', '', '', '', '']);
  const [method] = useState<MfaMethod>(challenge?.method || 'totp');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [useBackupCode, setUseBackupCode] = useState(false);

  const inputRefs = useRef<(HTMLInputElement | null)[]>([]);

  // Focus first input on mount
  useEffect(() => {
    if (!useBackupCode) {
      inputRefs.current[0]?.focus();
    }
  }, [useBackupCode]);

  const handleChange = useCallback((index: number, value: string) => {
    // Only allow digits
    if (!/^\d*$/.test(value)) return;

    const newCode = [...code];
    newCode[index] = value.slice(-1); // Only take last character
    setCode(newCode);
    setError(null);

    // Auto-focus next input
    if (value && index < 5) {
      inputRefs.current[index + 1]?.focus();
    }
  }, [code]);

  const handleKeyDown = useCallback((index: number, e: React.KeyboardEvent) => {
    if (e.key === 'Backspace' && !code[index] && index > 0) {
      // Move to previous input on backspace if current is empty
      inputRefs.current[index - 1]?.focus();
    }
  }, [code]);

  const handlePaste = useCallback((e: React.ClipboardEvent) => {
    e.preventDefault();
    const pastedData = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, 6);

    const newCode = [...code];
    pastedData.split('').forEach((digit, i) => {
      if (i < 6) newCode[i] = digit;
    });
    setCode(newCode);

    // Focus appropriate input
    const focusIndex = Math.min(pastedData.length, 5);
    inputRefs.current[focusIndex]?.focus();
  }, [code]);

  const handleSubmit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setError(null);

    const fullCode = code.join('');

    if (fullCode.length !== 6) {
      setError('Please enter a complete code');
      setIsLoading(false);
      return;
    }

    try {
      await verifyMfa(fullCode, useBackupCode ? 'backup_codes' : method);
      onVerify?.();
    } catch (err: any) {
      const errorMessage = err.message || 'Invalid code. Please try again.';
      setError(errorMessage);
      onError?.(err as ApiError);
      // Clear code on error
      setCode(['', '', '', '', '', '']);
      inputRefs.current[0]?.focus();
    } finally {
      setIsLoading(false);
    }
  }, [code, method, useBackupCode, verifyMfa, onVerify, onError]);

  const handleBackupCodeToggle = useCallback(() => {
    setUseBackupCode(!useBackupCode);
    setCode(['', '', '', '', '', '']);
    setError(null);
  }, [useBackupCode]);

  const getMethodLabel = (m: MfaMethod): string => {
    switch (m) {
      case 'totp':
        return 'authenticator app';
      case 'email':
        return 'email';
      case 'sms':
        return 'SMS';
      case 'webauthn':
        return 'security key';
      default:
        return m;
    }
  };

  // If not in MFA state and no challenge provided, show nothing
  if (!isRequired && !challenge && !propChallenge) {
    return null;
  }

  return (
    <Card className={className} centered width="sm">
      <CardHeader
        title="Two-factor authentication"
        subtitle={
          useBackupCode
            ? 'Enter one of your backup codes to continue.'
            : `Enter the 6-digit code from your ${getMethodLabel(method)}.`
        }
      />

      <CardContent>
        <LockIcon />

        {error && (
          <Alert variant="error" style={{ marginBottom: '1rem' }}>
            {error}
          </Alert>
        )}

        <form onSubmit={handleSubmit}>
          {!useBackupCode ? (
            <div
              style={{
                display: 'flex',
                justifyContent: 'center',
                gap: '0.5rem',
                marginBottom: '1.5rem',
              }}
            >
              {code.map((digit, index) => (
                <input
                  key={index}
                  ref={(el) => { inputRefs.current[index] = el; }}
                  type="text"
                  inputMode="numeric"
                  maxLength={1}
                  value={digit}
                  onChange={(e) => handleChange(index, e.target.value)}
                  onKeyDown={(e) => handleKeyDown(index, e)}
                  onPaste={handlePaste}
                  disabled={isLoading}
                  style={{
                    width: '3rem',
                    height: '3.5rem',
                    fontSize: '1.5rem',
                    fontWeight: 600,
                    textAlign: 'center',
                    fontFamily: cssVariables['--vault-font-family'],
                    color: cssVariables['--vault-color-input-text'],
                    backgroundColor: cssVariables['--vault-color-input-background'],
                    border: `2px solid ${cssVariables['--vault-color-input-border']}`,
                    borderRadius: cssVariables['--vault-border-radius'],
                    outline: 'none',
                    transition: 'all 0.15s ease-in-out',
                  }}
                  aria-label={`Digit ${index + 1}`}
                />
              ))}
            </div>
          ) : (
            <div style={{ marginBottom: '1.5rem' }}>
              <input
                type="text"
                value={code.join('')}
                onChange={(e) => {
                  const value = e.target.value.replace(/\D/g, '').slice(0, 6);
                  const newCode = value.split('').concat(Array(6 - value.length).fill(''));
                  setCode(newCode as string[]);
                }}
                placeholder="Enter backup code"
                disabled={isLoading}
                style={{
                  width: '100%',
                  padding: '0.75rem',
                  fontSize: '1.125rem',
                  textAlign: 'center',
                  letterSpacing: '0.25rem',
                  fontFamily: cssVariables['--vault-font-family'],
                  color: cssVariables['--vault-color-input-text'],
                  backgroundColor: cssVariables['--vault-color-input-background'],
                  border: `2px solid ${cssVariables['--vault-color-input-border']}`,
                  borderRadius: cssVariables['--vault-border-radius'],
                  outline: 'none',
                  boxSizing: 'border-box',
                }}
              />
            </div>
          )}

          <Button
            type="submit"
            isLoading={isLoading}
            disabled={code.join('').length !== 6}
          >
            Verify
          </Button>
        </form>

        {allowBackupCode && (
          <Button
            variant="ghost"
            onClick={handleBackupCodeToggle}
            style={{ marginTop: '0.5rem' }}
          >
            {useBackupCode
              ? 'Use authenticator code instead'
              : 'Use backup code instead'
            }
          </Button>
        )}
      </CardContent>

      <div
        style={{
          padding: '1rem 1.5rem 1.5rem',
          textAlign: 'center',
          borderTop: `1px solid ${cssVariables['--vault-color-border']}`,
        }}
      >
        <p
          style={{
            fontSize: '0.8125rem',
            fontFamily: cssVariables['--vault-font-family'],
            color: cssVariables['--vault-color-text-secondary'],
            margin: 0,
          }}
        >
          Having trouble?{' '}
          <a
            href="/support"
            style={{
              color: cssVariables['--vault-color-primary'],
              textDecoration: 'none',
            }}
          >
            Contact support
          </a>
        </p>
      </div>
    </Card>
  );
}

// Lock Icon Component
function LockIcon() {
  const { cssVariables } = useTheme();

  return (
    <div style={{ textAlign: 'center', marginBottom: '1rem' }}>
      <svg
        width="48"
        height="48"
        viewBox="0 0 24 24"
        fill="none"
        stroke={cssVariables['--vault-color-primary']}
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <rect x="5" y="11" width="14" height="10" rx="2" />
        <circle cx="12" cy="16" r="1" />
        <path d="M8 11V7a4 4 0 0 1 8 0v4" />
      </svg>
    </div>
  );
}
