/**
 * Alert Component
 *
 * Themed alert component for error, success, and warning messages.
 */

import React from 'react';
import { useTheme } from '../../theme';

// ============================================================================
// Types
// ============================================================================

export type AlertVariant = 'error' | 'success' | 'warning' | 'info';

export interface AlertProps extends React.HTMLAttributes<HTMLDivElement> {
  /** Alert variant */
  variant?: AlertVariant;
  /** Alert title */
  title?: string;
  /** Show icon */
  showIcon?: boolean;
  /** Custom icon */
  icon?: React.ReactNode;
  /** Dismissible alert */
  onDismiss?: () => void;
}

// ============================================================================
// Icons
// ============================================================================

const ErrorIcon = ({ color }: { color: string }) => (
  <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
    <path
      fillRule="evenodd"
      clipRule="evenodd"
      d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z"
      fill={color}
    />
  </svg>
);

const SuccessIcon = ({ color }: { color: string }) => (
  <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
    <path
      fillRule="evenodd"
      clipRule="evenodd"
      d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z"
      fill={color}
    />
  </svg>
);

const WarningIcon = ({ color }: { color: string }) => (
  <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
    <path
      fillRule="evenodd"
      clipRule="evenodd"
      d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z"
      fill={color}
    />
  </svg>
);

const InfoIcon = ({ color }: { color: string }) => (
  <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
    <path
      fillRule="evenodd"
      clipRule="evenodd"
      d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z"
      fill={color}
    />
  </svg>
);

const icons: Record<AlertVariant, React.FC<{ color: string }>> = {
  error: ErrorIcon,
  success: SuccessIcon,
  warning: WarningIcon,
  info: InfoIcon,
};

// ============================================================================
// Component
// ============================================================================

export function Alert({
  variant = 'info',
  title,
  showIcon = true,
  icon,
  onDismiss,
  children,
  className,
  style,
  ...props
}: AlertProps) {
  const { getElementClass, cssVariables } = useTheme();

  const variantColors: Record<AlertVariant, string> = {
    error: cssVariables['--vault-color-danger'],
    success: cssVariables['--vault-color-success'],
    warning: cssVariables['--vault-color-warning'],
    info: cssVariables['--vault-color-primary'],
  };

  const variantClasses: Record<AlertVariant, string> = {
    error: getElementClass('alertError'),
    success: getElementClass('alertSuccess'),
    warning: getElementClass('alertWarning'),
    info: getElementClass('alert'),
  };

  const color = variantColors[variant];
  const Icon = icons[variant];

  return (
    <div
      className={[getElementClass('alert'), variantClasses[variant], className]
        .filter(Boolean)
        .join(' ')}
      style={{
        display: 'flex',
        alignItems: 'flex-start',
        gap: '0.75rem',
        ...style,
      }}
      role={variant === 'error' ? 'alert' : 'status'}
      {...props}
    >
      {showIcon && (
        <div style={{ flexShrink: 0, marginTop: '0.125rem' }}>
          {icon || <Icon color={color} />}
        </div>
      )}
      <div style={{ flex: 1, minWidth: 0 }}>
        {title && (
          <div
            style={{
              fontWeight: 600,
              marginBottom: children ? '0.25rem' : 0,
              color,
            }}
          >
            {title}
          </div>
        )}
        {children && (
          <div style={{ color }}>{children}</div>
        )}
      </div>
      {onDismiss && (
        <button
          type="button"
          onClick={onDismiss}
          style={{
            flexShrink: 0,
            padding: '0.25rem',
            margin: '-0.25rem',
            background: 'none',
            border: 'none',
            cursor: 'pointer',
            color,
            opacity: 0.6,
            transition: 'opacity 0.15s ease-in-out',
          }}
          aria-label="Dismiss"
        >
          <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
            <path d="M4.646 4.646a.5.5 0 0 1 .708 0L8 7.293l2.646-2.647a.5.5 0 0 1 .708.708L8.707 8l2.647 2.646a.5.5 0 0 1-.708.708L8 8.707l-2.646 2.647a.5.5 0 0 1-.708-.708L7.293 8 4.646 5.354a.5.5 0 0 1 0-.708z" />
          </svg>
        </button>
      )}
    </div>
  );
}
