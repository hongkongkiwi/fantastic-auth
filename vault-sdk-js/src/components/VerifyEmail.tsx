/**
 * VerifyEmail Component
 * 
 * Email verification component that handles the verification token.
 * 
 * @example
 * ```tsx
 * // With token from URL
 * const token = new URLSearchParams(window.location.search).get('token');
 * <VerifyEmail 
 *   token={token}
 *   onVerified={() => navigate('/dashboard')}
 * />
 * 
 * // Resend verification
 * <VerifyEmail resendMode />
 * ```
 */

import React, { useState, useEffect, useCallback } from 'react';
import { useVault } from '../context/VaultContext';
import { VerifyEmailProps, ApiError } from '../types';

export type { VerifyEmailProps };

export function VerifyEmail({
  token,
  onVerified,
  onError,
  redirectUrl,
  appearance,
  className,
}: VerifyEmailProps) {
  const { verifyEmail, resendVerificationEmail, user } = useVault();
  const [status, setStatus] = useState<'idle' | 'verifying' | 'success' | 'error'>('idle');
  const [error, setError] = useState<string | null>(null);
  const [resendStatus, setResendStatus] = useState<'idle' | 'sending' | 'sent'>('idle');

  // Auto-verify if token is provided
  useEffect(() => {
    if (token && status === 'idle') {
      handleVerify();
    }
  }, [token]);

  const handleVerify = useCallback(async () => {
    if (!token) return;

    setStatus('verifying');
    setError(null);

    try {
      await verifyEmail({ token });
      setStatus('success');
      onVerified?.();

      if (redirectUrl) {
        setTimeout(() => {
          window.location.href = redirectUrl;
        }, 2000);
      }
    } catch (err: any) {
      setStatus('error');
      const errorMessage = err.message || 'Failed to verify email';
      setError(errorMessage);
      onError?.(err as ApiError);
    }
  }, [token, verifyEmail, onVerified, onError, redirectUrl]);

  const handleResend = useCallback(async () => {
    setResendStatus('sending');
    setError(null);

    try {
      await resendVerificationEmail();
      setResendStatus('sent');
    } catch (err: any) {
      const errorMessage = err.message || 'Failed to resend verification email';
      setError(errorMessage);
      onError?.(err as ApiError);
    }
  }, [resendVerificationEmail, onError]);

  // No token provided - show resend option
  if (!token) {
    return (
      <div style={applyAppearance(styles.container, appearance)} className={className}>
        <div style={styles.content}>
          <EmailIcon />
          <h2 style={applyAppearance(styles.title, appearance)}>
            Verify your email
          </h2>
          <p style={styles.description}>
            {user?.emailVerified 
              ? 'Your email is already verified.'
              : `We've sent a verification link to ${user?.email || 'your email address'}. Please check your inbox and click the link to verify.`
            }
          </p>
          
          {!user?.emailVerified && (
            <>
              <button
                onClick={handleResend}
                disabled={resendStatus === 'sending' || resendStatus === 'sent'}
                style={applyAppearance(styles.button, appearance)}
              >
                {resendStatus === 'sending' 
                  ? 'Sending...' 
                  : resendStatus === 'sent' 
                    ? 'Email sent!' 
                    : 'Resend verification email'
                }
              </button>
              
              {error && (
                <div style={applyAppearance(styles.error, appearance)} role="alert">
                  {error}
                </div>
              )}
            </>
          )}
        </div>
      </div>
    );
  }

  // Show appropriate state based on verification status
  return (
    <div style={applyAppearance(styles.container, appearance)} className={className}>
      <div style={styles.content}>
        {status === 'verifying' && (
          <>
            <div style={styles.spinner} />
            <h2 style={applyAppearance(styles.title, appearance)}>
              Verifying your email...
            </h2>
          </>
        )}

        {status === 'success' && (
          <>
            <SuccessIcon />
            <h2 style={applyAppearance(styles.title, appearance)}>
              Email verified!
            </h2>
            <p style={styles.description}>
              Your email has been successfully verified.
              {redirectUrl && ' Redirecting you...'}
            </p>
          </>
        )}

        {status === 'error' && (
          <>
            <ErrorIcon />
            <h2 style={applyAppearance(styles.title, appearance)}>
              Verification failed
            </h2>
            <p style={styles.description}>
              {error || 'The verification link is invalid or has expired.'}
            </p>
            <div style={styles.buttonGroup}>
              <button
                onClick={handleResend}
                disabled={resendStatus === 'sending'}
                style={applyAppearance(styles.button, appearance)}
              >
                {resendStatus === 'sending' ? 'Sending...' : 'Resend email'}
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

// Icon Components
function EmailIcon() {
  return (
    <svg
      width="48"
      height="48"
      viewBox="0 0 24 24"
      fill="none"
      stroke="#0066cc"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      style={styles.icon}
    >
      <rect x="2" y="4" width="20" height="16" rx="2" />
      <path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7" />
    </svg>
  );
}

function SuccessIcon() {
  return (
    <svg
      width="48"
      height="48"
      viewBox="0 0 24 24"
      fill="none"
      stroke="#059669"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      style={styles.icon}
    >
      <circle cx="12" cy="12" r="10" />
      <path d="m9 12 2 2 4-4" />
    </svg>
  );
}

function ErrorIcon() {
  return (
    <svg
      width="48"
      height="48"
      viewBox="0 0 24 24"
      fill="none"
      stroke="#dc2626"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      style={styles.icon}
    >
      <circle cx="12" cy="12" r="10" />
      <line x1="15" y1="9" x2="9" y2="15" />
      <line x1="9" y1="9" x2="15" y2="15" />
    </svg>
  );
}

// Apply appearance variables
function applyAppearance(
  baseStyle: React.CSSProperties,
  appearance?: { theme?: string; variables?: Record<string, string>; elements?: Record<string, React.CSSProperties> }
): React.CSSProperties {
  if (!appearance) return baseStyle;

  const variables = appearance.variables || {};
  let style = { ...baseStyle };

  if (variables['colorPrimary']) {
    if (baseStyle.color === '#0066cc' || baseStyle.borderColor === '#0066cc' || baseStyle.backgroundColor === '#0066cc') {
      style = { 
        ...style, 
        color: baseStyle.color === '#0066cc' ? variables['colorPrimary'] : style.color,
        borderColor: baseStyle.borderColor === '#0066cc' ? variables['colorPrimary'] : style.borderColor,
        backgroundColor: baseStyle.backgroundColor === '#0066cc' ? variables['colorPrimary'] : style.backgroundColor,
      };
    }
  }

  if (variables['borderRadius'] && baseStyle.borderRadius) {
    style = { ...style, borderRadius: variables['borderRadius'] };
  }

  return style;
}

// Styles
const styles: Record<string, React.CSSProperties> = {
  container: {
    maxWidth: '400px',
    margin: '0 auto',
    padding: '24px',
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
  },
  content: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    textAlign: 'center',
    padding: '24px',
  },
  icon: {
    marginBottom: '16px',
  },
  title: {
    fontSize: '22px',
    fontWeight: 600,
    margin: '0 0 12px',
    color: '#1f2937',
  },
  description: {
    fontSize: '15px',
    color: '#6b7280',
    margin: '0 0 24px',
    lineHeight: 1.5,
  },
  button: {
    padding: '12px 24px',
    fontSize: '15px',
    fontWeight: 500,
    color: '#fff',
    backgroundColor: '#0066cc',
    border: 'none',
    borderRadius: '6px',
    cursor: 'pointer',
    transition: 'background-color 0.15s ease-in-out',
  },
  buttonGroup: {
    display: 'flex',
    gap: '12px',
  },
  error: {
    marginTop: '16px',
    padding: '12px',
    fontSize: '14px',
    color: '#dc2626',
    backgroundColor: '#fee2e2',
    borderRadius: '6px',
  },
  spinner: {
    width: '48px',
    height: '48px',
    border: '3px solid #e5e7eb',
    borderTopColor: '#0066cc',
    borderRadius: '50%',
    animation: 'spin 1s linear infinite',
    marginBottom: '16px',
  },
};
