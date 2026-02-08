/**
 * SocialButton Component
 *
 * Themed OAuth/social login buttons.
 */

import React from 'react';
import { useTheme } from '../../theme';

// ============================================================================
// Types
// ============================================================================

export type OAuthProvider = 'google' | 'github' | 'microsoft' | 'apple' | 'facebook' | 'twitter';

export interface SocialButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  /** OAuth provider */
  provider: OAuthProvider;
  /** Button variant */
  variant?: 'block' | 'icon';
  /** Custom label (overrides default) */
  label?: string;
  /** Loading state */
  isLoading?: boolean;
  /** Custom class name */
  elementClassName?: string;
}

// ============================================================================
// Icons
// ============================================================================

const GoogleIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24">
    <path
      fill="#4285F4"
      d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
    />
    <path
      fill="#34A853"
      d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
    />
    <path
      fill="#FBBC05"
      d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
    />
    <path
      fill="#EA4335"
      d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
    />
  </svg>
);

const GitHubIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
    <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
  </svg>
);

const MicrosoftIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24">
    <path fill="#f25022" d="M1 1h10v10H1z" />
    <path fill="#00a4ef" d="M1 13h10v10H1z" />
    <path fill="#7fba00" d="M13 1h10v10H13z" />
    <path fill="#ffb900" d="M13 13h10v10H13z" />
  </svg>
);

const AppleIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
    <path d="M17.05 20.28c-.98.95-2.05.88-3.08.4-1.09-.5-2.08-.48-3.24 0-1.44.62-2.2.44-3.06-.4C2.79 15.25 3.51 7.59 9.05 7.31c1.35.07 2.29.74 3.08.8 1.18-.24 2.31-.93 3.57-.84 1.51.12 2.65.72 3.4 1.8-3.12 1.87-2.38 5.98.22 7.13-.57 1.5-1.31 2.99-2.27 4.08zm-5.85-15.1c.07-2.04 1.76-3.79 3.78-3.94.29 2.32-1.93 4.48-3.78 3.94z" />
  </svg>
);

const FacebookIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="#1877F2">
    <path d="M24 12.073c0-6.627-5.373-12-12-12s-12 5.373-12 12c0 5.99 4.388 10.954 10.125 11.854v-8.385H7.078v-3.47h3.047V9.43c0-3.007 1.792-4.669 4.533-4.669 1.312 0 2.686.235 2.686.235v2.953H15.83c-1.491 0-1.956.925-1.956 1.874v2.25h3.328l-.532 3.47h-2.796v8.385C19.612 23.027 24 18.062 24 12.073z" />
  </svg>
);

const TwitterIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
    <path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z" />
  </svg>
);

const icons: Record<OAuthProvider, React.FC> = {
  google: GoogleIcon,
  github: GitHubIcon,
  microsoft: MicrosoftIcon,
  apple: AppleIcon,
  facebook: FacebookIcon,
  twitter: TwitterIcon,
};

const labels: Record<OAuthProvider, string> = {
  google: 'Continue with Google',
  github: 'Continue with GitHub',
  microsoft: 'Continue with Microsoft',
  apple: 'Continue with Apple',
  facebook: 'Continue with Facebook',
  twitter: 'Continue with X',
};

// ============================================================================
// Component
// ============================================================================

export function SocialButton({
  provider,
  variant = 'block',
  label,
  isLoading,
  elementClassName,
  disabled,
  style,
  children,
  ...props
}: SocialButtonProps) {
  const { getElementClass, cssVariables } = useTheme();

  const Icon = icons[provider];
  const buttonLabel = label || labels[provider];

  // Block button style
  const blockStyle: React.CSSProperties = {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '0.75rem',
    width: '100%',
    padding: '0.75rem 1rem',
    fontSize: cssVariables['--vault-font-size'],
    fontWeight: 500,
    fontFamily: cssVariables['--vault-font-family-buttons'],
    color: cssVariables['--vault-color-text'],
    backgroundColor: cssVariables['--vault-color-surface'],
    border: `1px solid ${cssVariables['--vault-color-border']}`,
    borderRadius: cssVariables['--vault-border-radius'],
    cursor: 'pointer',
    transition: 'background-color 0.15s ease-in-out, border-color 0.15s ease-in-out',
  };

  // Icon button style
  const iconStyle: React.CSSProperties = {
    display: 'inline-flex',
    alignItems: 'center',
    justifyContent: 'center',
    width: '2.75rem',
    height: '2.75rem',
    padding: 0,
    backgroundColor: cssVariables['--vault-color-surface'],
    border: `1px solid ${cssVariables['--vault-color-border']}`,
    borderRadius: cssVariables['--vault-border-radius'],
    cursor: 'pointer',
    transition: 'background-color 0.15s ease-in-out, border-color 0.15s ease-in-out',
  };

  const isIconVariant = variant === 'icon';
  const baseClassName = isIconVariant
    ? getElementClass('socialButtonsIconButton')
    : getElementClass('socialButtons');

  return (
    <button
      type="button"
      className={[baseClassName, elementClassName].filter(Boolean).join(' ')}
      style={{
        ...(isIconVariant ? iconStyle : blockStyle),
        opacity: disabled || isLoading ? 0.6 : 1,
        cursor: disabled || isLoading ? 'not-allowed' : 'pointer',
        ...style,
      }}
      disabled={disabled || isLoading}
      {...props}
    >
      {isLoading ? (
        <span
          className="vault-spinner"
          style={{
            width: '1rem',
            height: '1rem',
          }}
        />
      ) : (
        <Icon />
      )}
      {!isIconVariant && <span>{buttonLabel}</span>}
      {children}
    </button>
  );
}

// ============================================================================
// SocialButtons Container
// ============================================================================

export interface SocialButtonsProps {
  /** Social buttons to render */
  children: React.ReactNode;
  /** Layout variant */
  layout?: 'vertical' | 'horizontal';
  /** Custom class name */
  className?: string;
}

export function SocialButtons({
  children,
  layout = 'vertical',
  className,
}: SocialButtonsProps) {
  const { getElementClass } = useTheme();

  const layoutStyles: Record<string, React.CSSProperties> = {
    vertical: {
      display: 'flex',
      flexDirection: 'column',
      gap: '0.5rem',
    },
    horizontal: {
      display: 'flex',
      flexDirection: 'row',
      gap: '0.5rem',
      justifyContent: 'center',
    },
  };

  return (
    <div
      className={[getElementClass('socialButtons'), className]
        .filter(Boolean)
        .join(' ')}
      style={layoutStyles[layout]}
    >
      {children}
    </div>
  );
}
