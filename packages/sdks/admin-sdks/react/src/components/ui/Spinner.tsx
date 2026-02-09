/**
 * Spinner Component
 * 
 * Loading indicator component.
 */

import React from 'react';
import type { SpinnerProps } from '../../types';
import { classNames } from '../../styles';

const sizeMap = {
  sm: 'vault-spinner-sm',
  md: 'vault-spinner-md',
  lg: 'vault-spinner-lg',
};

/**
 * Spinner component for loading states
 */
export const Spinner: React.FC<SpinnerProps> = ({ 
  size = 'md', 
  className 
}) => {
  return (
    <span 
      className={classNames('vault-spinner', sizeMap[size], className)}
      role="status"
      aria-label="Loading"
    >
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
  );
};
