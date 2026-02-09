/**
 * Spinner Component
 *
 * Themed loading spinner with optional shimmer effect.
 */

import React from 'react';
import { useTheme } from '../../theme';

// ============================================================================
// Types
// ============================================================================

export interface SpinnerProps {
  /** Spinner size */
  size?: 'sm' | 'md' | 'lg' | 'xl' | number;
  /** Use shimmer animation instead of spin */
  shimmer?: boolean;
  /** Shimmer width (for block shimmer) */
  shimmerWidth?: string | number;
  /** Shimmer height (for block shimmer) */
  shimmerHeight?: string | number;
  /** Custom class name */
  className?: string;
  /** Custom style */
  style?: React.CSSProperties;
}

// ============================================================================
// Component
// ============================================================================

export function Spinner({
  size = 'md',
  shimmer,
  shimmerWidth = '100%',
  shimmerHeight = '1rem',
  className,
  style,
}: SpinnerProps) {
  const { cssVariables, getLayoutOption } = useTheme();
  const useShimmer = shimmer ?? getLayoutOption('shimmer');

  // Size map
  const sizeMap: Record<string, number> = {
    sm: 16,
    md: 20,
    lg: 32,
    xl: 48,
  };

  const sizeValue = typeof size === 'number' ? size : sizeMap[size];

  // Shimmer style
  if (useShimmer) {
    const width = typeof shimmerWidth === 'number' ? `${shimmerWidth}px` : shimmerWidth;
    const height = typeof shimmerHeight === 'number' ? `${shimmerHeight}px` : shimmerHeight;

    return (
      <div
        className={['vault-shimmer', className].filter(Boolean).join(' ')}
        style={{
          width,
          height,
          borderRadius: cssVariables['--vault-border-radius'],
          ...style,
        }}
      />
    );
  }

  // Spinner style
  return (
    <div
      className={['vault-spinner', className].filter(Boolean).join(' ')}
      style={{
        width: sizeValue,
        height: sizeValue,
        border: `2px solid ${cssVariables['--vault-color-border']}`,
        borderTopColor: cssVariables['--vault-color-primary'],
        borderRadius: '50%',
        animation: 'vault-spin 1s linear infinite',
        ...style,
      }}
      role="status"
      aria-label="Loading"
    />
  );
}

// ============================================================================
// Spinner Overlay
// ============================================================================

export interface SpinnerOverlayProps {
  /** Whether to show overlay */
  isLoading: boolean;
  /** Children to render */
  children: React.ReactNode;
  /** Spinner size */
  size?: SpinnerProps['size'];
  /** Use shimmer */
  shimmer?: boolean;
  /** Overlay opacity */
  opacity?: number;
  /** Custom class name */
  className?: string;
}

export function SpinnerOverlay({
  isLoading,
  children,
  size = 'lg',
  shimmer,
  opacity = 0.7,
  className,
}: SpinnerOverlayProps) {
  const { cssVariables } = useTheme();

  return (
    <div
      className={className}
      style={{
        position: 'relative',
        display: 'inline-block',
      }}
    >
      {children}
      {isLoading && (
        <div
          style={{
            position: 'absolute',
            inset: 0,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            backgroundColor: cssVariables['--vault-color-background'],
            opacity,
            borderRadius: 'inherit',
          }}
        >
          <Spinner size={size} shimmer={shimmer} />
        </div>
      )}
    </div>
  );
}

// ============================================================================
// Skeleton Loader
// ============================================================================

export interface SkeletonProps {
  /** Number of skeleton lines */
  lines?: number;
  /** Line height */
  lineHeight?: string | number;
  /** Gap between lines */
  gap?: string | number;
  /** Custom class name */
  className?: string;
}

export function Skeleton({
  lines = 3,
  lineHeight = '1rem',
  gap = '0.5rem',
  className,
}: SkeletonProps) {
  const lineHeightValue = typeof lineHeight === 'number' ? `${lineHeight}px` : lineHeight;
  const gapValue = typeof gap === 'number' ? `${gap}px` : gap;

  return (
    <div
      className={className}
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: gapValue,
      }}
    >
      {Array.from({ length: lines }).map((_, index) => (
        <Spinner
          key={index}
          shimmer
          shimmerWidth={index === lines - 1 ? '60%' : '100%'}
          shimmerHeight={lineHeightValue}
        />
      ))}
    </div>
  );
}
