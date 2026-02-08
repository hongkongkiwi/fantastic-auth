/**
 * Input Component
 *
 * Themed input component with label, error states, and full theming support.
 */

import React, { forwardRef } from 'react';
import { useTheme } from '../../theme';

// ============================================================================
// Types
// ============================================================================

export interface InputProps extends Omit<React.InputHTMLAttributes<HTMLInputElement>, 'size'> {
  /** Input label */
  label?: string;
  /** Error message */
  error?: string;
  /** Helper text */
  helperText?: string;
  /** Custom input class name */
  inputClassName?: string;
  /** Custom label class name */
  labelClassName?: string;
  /** Custom error class name */
  errorClassName?: string;
  /** Custom field container class name */
  fieldClassName?: string;
  /** Input size */
  size?: 'sm' | 'md' | 'lg';
}

// ============================================================================
// Component
// ============================================================================

export const Input = forwardRef<HTMLInputElement, InputProps>(
  (
    {
      label,
      error,
      helperText,
      id,
      disabled,
      required,
      inputClassName,
      labelClassName,
      errorClassName,
      fieldClassName,
      size = 'md',
      style,
      ...props
    },
    ref
  ) => {
    const { getElementClass, cssVariables } = useTheme();

    // Generate unique ID if not provided
    const inputId = id || `vault-input-${Math.random().toString(36).slice(2, 11)}`;

    // Size styles
    const sizeStyles: Record<string, React.CSSProperties> = {
      sm: {
        padding: '0.375rem 0.5rem',
        fontSize: '0.875rem',
      },
      md: {
        padding: '0.625rem 0.75rem',
        fontSize: cssVariables['--vault-font-size'],
      },
      lg: {
        padding: '0.875rem 1rem',
        fontSize: '1.125rem',
      },
    };

    // Error state style
    const errorStyle: React.CSSProperties = error
      ? {
          borderColor: cssVariables['--vault-color-danger'],
        }
      : {};

    const inputStyle: React.CSSProperties = {
      ...sizeStyles[size],
      ...errorStyle,
      ...style,
    };

    return (
      <div
        className={[getElementClass('formField'), fieldClassName]
          .filter(Boolean)
          .join(' ')}
      >
        {label && (
          <label
            htmlFor={inputId}
            className={[getElementClass('formFieldLabel'), labelClassName]
              .filter(Boolean)
              .join(' ')}
          >
            {label}
            {required && (
              <span style={{ color: cssVariables['--vault-color-danger'], marginLeft: '0.25rem' }}>
                *
              </span>
            )}
          </label>
        )}
        <input
          ref={ref}
          id={inputId}
          className={[getElementClass('formFieldInput'), inputClassName]
            .filter(Boolean)
            .join(' ')}
          style={inputStyle}
          disabled={disabled}
          aria-invalid={error ? 'true' : 'false'}
          aria-describedby={error ? `${inputId}-error` : undefined}
          {...props}
        />
        {error && (
          <span
            id={`${inputId}-error`}
            className={[getElementClass('formFieldError'), errorClassName]
              .filter(Boolean)
              .join(' ')}
            role="alert"
          >
            {error}
          </span>
        )}
        {helperText && !error && (
          <span
            style={{
              display: 'block',
              marginTop: '0.375rem',
              fontSize: '0.75rem',
              fontFamily: cssVariables['--vault-font-family'],
              color: cssVariables['--vault-color-text-secondary'],
            }}
          >
            {helperText}
          </span>
        )}
      </div>
    );
  }
);

Input.displayName = 'Input';
