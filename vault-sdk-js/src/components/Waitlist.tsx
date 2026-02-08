/**
 * Waitlist Component
 *
 * Email waitlist signup form with success state and optional social proof.
 *
 * @example
 * ```tsx
 * <Waitlist
 *   onSubmit={(email) => console.log('Joined:', email)}
 *   socialProof="Join 1,000+ others"
 * />
 * ```
 */

import React, { useState, useCallback } from 'react';
import { Appearance, ApiError } from '../types';

export interface WaitlistProps {
  /**
   * Callback when email is submitted
   */
  onSubmit?: (email: string) => void;
  /**
   * Redirect URL after successful submission
   */
  redirectUrl?: string;
  /**
   * Custom styling
   */
  appearance?: Appearance;
  /**
   * Social proof text (e.g., "Join 1,000+ others")
   */
  socialProof?: string;
  /**
   * Custom class name
   */
  className?: string;
}

export function Waitlist({
  onSubmit,
  redirectUrl,
  appearance,
  socialProof,
  className,
}: WaitlistProps) {
  const [email, setEmail] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    // Validate email
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!email.trim()) {
      setError('Please enter your email address');
      return;
    }
    if (!emailRegex.test(email)) {
      setError('Please enter a valid email address');
      return;
    }

    setIsLoading(true);

    try {
      // Call the onSubmit callback if provided
      await onSubmit?.(email);
      
      setIsSuccess(true);
      
      // Redirect after a short delay if redirectUrl is provided
      if (redirectUrl) {
        setTimeout(() => {
          window.location.href = redirectUrl;
        }, 2000);
      }
    } catch (err) {
      setError((err as ApiError).message || 'Something went wrong. Please try again.');
    } finally {
      setIsLoading(false);
    }
  }, [email, onSubmit, redirectUrl]);

  if (isSuccess) {
    return (
      <div style={applyAppearance(styles.container, appearance)} className={className}>
        <div style={styles.successState}>
          <div style={styles.successIcon}>
            <CheckIcon />
          </div>
          <h2 style={applyAppearance(styles.successTitle, appearance)}>
            You&apos;re on the list!
          </h2>
          <p style={styles.successText}>
            We&apos;ve added <strong>{email}</strong> to our waitlist.
            We&apos;ll notify you when spots become available.
          </p>
          {redirectUrl && (
            <p style={styles.redirectText}>
              Redirecting you...
            </p>
          )}
        </div>
      </div>
    );
  }

  return (
    <div style={applyAppearance(styles.container, appearance)} className={className}>
      <div style={styles.header}>
        <h2 style={applyAppearance(styles.title, appearance)}>
          Join the Waitlist
        </h2>
        <p style={styles.subtitle}>
          Be the first to know when we launch. No spam, ever.
        </p>
      </div>

      {socialProof && (
        <div style={styles.socialProof}>
          <UsersIcon />
          <span>{socialProof}</span>
        </div>
      )}

      <form onSubmit={handleSubmit} style={styles.form}>
        {error && (
          <div style={applyAppearance(styles.error, appearance)} role="alert">
            {error}
          </div>
        )}

        <div style={styles.inputGroup}>
          <input
            id="vault-waitlist-email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="Enter your email"
            required
            disabled={isLoading}
            style={applyAppearance(styles.input, appearance)}
            aria-label="Email address"
          />
          <button
            type="submit"
            disabled={isLoading || !email.trim()}
            style={applyAppearance(styles.submitButton, appearance)}
          >
            {isLoading ? (
              <>
                <Spinner />
                <span>Joining...</span>
              </>
            ) : (
              <>
                <span>Join Waitlist</span>
                <ArrowRightIcon />
              </>
            )}
          </button>
        </div>

        <p style={styles.privacy}>
          By joining, you agree to our Terms of Service and Privacy Policy.
        </p>
      </form>
    </div>
  );
}

// Icon Components
function CheckIcon() {
  return (
    <svg
      width="32"
      height="32"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="3"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <polyline points="20 6 9 17 4 12" />
    </svg>
  );
}

function UsersIcon() {
  return (
    <svg
      width="16"
      height="16"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
      <circle cx="9" cy="7" r="4" />
      <path d="M23 21v-2a4 4 0 0 0-3-3.87" />
      <path d="M16 3.13a4 4 0 0 1 0 7.75" />
    </svg>
  );
}

function ArrowRightIcon() {
  return (
    <svg
      width="16"
      height="16"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <line x1="5" y1="12" x2="19" y2="12" />
      <polyline points="12 5 19 12 12 19" />
    </svg>
  );
}

function Spinner() {
  return (
    <div style={styles.spinner}>
      <div style={styles.spinnerInner} />
    </div>
  );
}

// Apply appearance variables
function applyAppearance(
  baseStyle: React.CSSProperties,
  appearance?: Appearance
): React.CSSProperties {
  if (!appearance) return baseStyle;

  const variables = appearance.variables || {};
  let style = { ...baseStyle };

  if (variables['colorPrimary']) {
    if (baseStyle.backgroundColor === '#0066cc' || baseStyle.borderColor === '#0066cc') {
      style = {
        ...style,
        backgroundColor: variables['colorPrimary'],
        borderColor: variables['colorPrimary'],
      };
    }
    if (baseStyle.color === '#0066cc') {
      style = { ...style, color: variables['colorPrimary'] };
    }
  }

  if (variables['borderRadius'] && baseStyle.borderRadius) {
    style = { ...style, borderRadius: variables['borderRadius'] };
  }

  if (variables['fontSize'] && baseStyle.fontSize) {
    style = { ...style, fontSize: variables['fontSize'] };
  }

  return style;
}

// Styles
const styles: Record<string, React.CSSProperties> = {
  container: {
    maxWidth: '400px',
    margin: '0 auto',
    padding: '32px 24px',
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
  },
  header: {
    textAlign: 'center',
    marginBottom: '24px',
  },
  title: {
    margin: '0 0 8px',
    fontSize: '24px',
    fontWeight: 700,
    color: '#1a1a1a',
  },
  subtitle: {
    margin: 0,
    fontSize: '15px',
    color: '#6b7280',
  },
  socialProof: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '6px',
    marginBottom: '20px',
    fontSize: '14px',
    color: '#059669',
  },
  form: {
    display: 'flex',
    flexDirection: 'column',
    gap: '12px',
  },
  error: {
    padding: '12px',
    color: '#dc2626',
    backgroundColor: '#fee2e2',
    borderRadius: '6px',
    fontSize: '14px',
  },
  inputGroup: {
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '8px',
  },
  input: {
    padding: '12px 16px',
    fontSize: '16px',
    border: '1px solid #d1d5db',
    borderRadius: '6px',
    outline: 'none',
    transition: 'border-color 0.15s ease-in-out',
  },
  submitButton: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '8px',
    padding: '12px 20px',
    fontSize: '16px',
    fontWeight: 600,
    color: '#fff',
    backgroundColor: '#0066cc',
    border: 'none',
    borderRadius: '6px',
    cursor: 'pointer',
    transition: 'background-color 0.15s ease-in-out',
  },
  privacy: {
    margin: '8px 0 0',
    fontSize: '12px',
    color: '#9ca3af',
    textAlign: 'center',
  },
  successState: {
    textAlign: 'center',
    padding: '24px 16px',
  },
  successIcon: {
    width: '64px',
    height: '64px',
    margin: '0 auto 20px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    color: '#fff',
    backgroundColor: '#10b981',
    borderRadius: '50%',
  },
  successTitle: {
    margin: '0 0 12px',
    fontSize: '22px',
    fontWeight: 700,
    color: '#1a1a1a',
  },
  successText: {
    margin: '0 0 16px',
    fontSize: '15px',
    color: '#6b7280',
    lineHeight: 1.6,
  },
  redirectText: {
    margin: 0,
    fontSize: '14px',
    color: '#9ca3af',
  },
  spinner: {
    width: '16px',
    height: '16px',
    animation: 'spin 1s linear infinite',
  },
  spinnerInner: {
    width: '100%',
    height: '100%',
    border: '2px solid rgba(255,255,255,0.3)',
    borderTopColor: '#fff',
    borderRadius: '50%',
  },
};
