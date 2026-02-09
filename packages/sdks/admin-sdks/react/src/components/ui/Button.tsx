/**
 * Button Component
 * 
 * Reusable button component with variants and loading state.
 */

import React from 'react';
import type { ButtonProps } from '../../types';
import { classNames } from '../../styles';

/**
 * Button component with multiple variants and sizes
 */
export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  (
    {
      children,
      variant = 'primary',
      size = 'md',
      isLoading = false,
      fullWidth = false,
      disabled,
      className,
      ...props
    },
    ref
  ) => {
    const baseStyles = 'vault-btn';
    
    const variantStyles = {
      primary: 'vault-btn-primary',
      secondary: 'vault-btn-secondary',
      outline: 'vault-btn-outline',
      ghost: 'vault-btn-ghost',
      danger: 'vault-btn-danger',
    };

    const sizeStyles = {
      sm: 'vault-btn-sm',
      md: 'vault-btn-md',
      lg: 'vault-btn-lg',
    };

    return (
      <button
        ref={ref}
        className={classNames(
          baseStyles,
          variantStyles[variant],
          sizeStyles[size],
          fullWidth && 'vault-btn-full',
          (disabled || isLoading) && 'vault-btn-disabled',
          className
        )}
        disabled={disabled || isLoading}
        aria-disabled={disabled || isLoading}
        aria-busy={isLoading}
        {...props}
      >
        {isLoading && (
          <span className="vault-btn-spinner" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <circle
                cx="12"
                cy="12"
                r="10"
                stroke="currentColor"
                strokeWidth="4"
                strokeLinecap="round"
                strokeDasharray="60"
                strokeDashoffset="20"
              />
            </svg>
          </span>
        )}
        <span className={classNames('vault-btn-content', isLoading && 'vault-btn-content-hidden')}>
          {children}
        </span>
      </button>
    );
  }
);

Button.displayName = 'Button';
