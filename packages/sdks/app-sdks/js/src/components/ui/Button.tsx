/**
 * Button Component
 *
 * Themed button component with primary and secondary variants.
 */

import React, { forwardRef } from 'react';
import { useTheme } from '../../theme';

// ============================================================================
// Types
// ============================================================================

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  /** Button visual variant */
  variant?: 'primary' | 'secondary' | 'ghost';
  /** Button size */
  size?: 'sm' | 'md' | 'lg';
  /** Loading state */
  isLoading?: boolean;
  /** Loading text (defaults to spinner) */
  loadingText?: string;
  /** Full width button */
  fullWidth?: boolean;
  /** Custom element class name */
  elementClassName?: string;
}

// ============================================================================
// Component
// ============================================================================

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  (
    {
      children,
      variant = 'primary',
      size = 'md',
      isLoading = false,
      loadingText,
      fullWidth = false,
      elementClassName,
      disabled,
      className,
      style,
      ...props
    },
    ref
  ) => {
    const { getElementClass, cssVariables } = useTheme();

    // Get base class name from theme
    const baseClassName =
      variant === 'primary'
        ? getElementClass('formButtonPrimary')
        : getElementClass('formButtonSecondary');

    // Combine class names
    const combinedClassName = [baseClassName, elementClassName, className]
      .filter(Boolean)
      .join(' ');

    // Size styles
    const sizeStyles: Record<string, React.CSSProperties> = {
      sm: {
        padding: '0.5rem 0.75rem',
        fontSize: '0.875rem',
      },
      md: {
        padding: '0.75rem 1rem',
        fontSize: cssVariables['--vault-font-size'],
      },
      lg: {
        padding: '1rem 1.25rem',
        fontSize: '1.125rem',
      },
    };

    // Variant-specific styles
    const variantStyles: Record<string, React.CSSProperties> = {
      primary: {},
      secondary: {},
      ghost: {
        backgroundColor: 'transparent',
        border: 'none',
        color: cssVariables['--vault-color-primary'],
      },
    };

    const buttonStyle: React.CSSProperties = {
      width: fullWidth ? '100%' : undefined,
      ...sizeStyles[size],
      ...variantStyles[variant],
      ...style,
    };

    return (
      <button
        ref={ref}
        className={combinedClassName}
        style={buttonStyle}
        disabled={disabled || isLoading}
        {...props}
      >
        {isLoading ? (
          <>
            <span
              className="vault-spinner"
              style={{
                width: '1rem',
                height: '1rem',
                marginRight: loadingText ? '0.5rem' : 0,
              }}
            />
            {loadingText}
          </>
        ) : (
          children
        )}
      </button>
    );
  }
);

Button.displayName = 'Button';
