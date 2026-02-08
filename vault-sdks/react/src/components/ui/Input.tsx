/**
 * Input Component
 * 
 * Reusable input component with label, error, and helper text support.
 */

import React from 'react';
import type { InputProps } from '../../types';
import { classNames } from '../../styles';

/**
 * Input component with label and validation support
 */
export const Input = React.forwardRef<HTMLInputElement, InputProps>(
  (
    {
      label,
      error,
      helperText,
      size = 'md',
      className,
      id,
      required,
      ...props
    },
    ref
  ) => {
    const inputId = id || React.useId();
    const errorId = `${inputId}-error`;
    const helperId = `${inputId}-helper`;

    const sizeStyles = {
      sm: 'vault-input-sm',
      md: 'vault-input-md',
      lg: 'vault-input-lg',
    };

    return (
      <div className={classNames('vault-input-wrapper', className)}>
        {label && (
          <label 
            htmlFor={inputId} 
            className="vault-input-label"
          >
            {label}
            {required && <span className="vault-input-required" aria-hidden="true"> *</span>}
          </label>
        )}
        <input
          ref={ref}
          id={inputId}
          className={classNames(
            'vault-input',
            sizeStyles[size],
            error && 'vault-input-error'
          )}
          aria-invalid={error ? 'true' : 'false'}
          aria-describedby={
            classNames(
              error && errorId,
              helperText && helperId
            ) || undefined
          }
          required={required}
          {...props}
        />
        {error && (
          <span id={errorId} className="vault-input-error-text" role="alert">
            {error}
          </span>
        )}
        {helperText && !error && (
          <span id={helperId} className="vault-input-helper">
            {helperText}
          </span>
        )}
      </div>
    );
  }
);

Input.displayName = 'Input';
