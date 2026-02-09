/**
 * Divider Component
 *
 * Themed divider with optional text.
 */

import React from 'react';
import { useTheme } from '../../theme';

// ============================================================================
// Types
// ============================================================================

export interface DividerProps {
  /** Divider text */
  text?: string;
  /** Vertical spacing */
  spacing?: 'sm' | 'md' | 'lg';
  /** Custom class name for the line */
  lineClassName?: string;
  /** Custom class name for the text */
  textClassName?: string;
}

// ============================================================================
// Component
// ============================================================================

export function Divider({
  text,
  spacing = 'md',
  lineClassName,
  textClassName,
}: DividerProps) {
  const { getElementClass, cssVariables } = useTheme();

  const spacingStyles: Record<string, React.CSSProperties> = {
    sm: { margin: '1rem 0' },
    md: { margin: '1.5rem 0' },
    lg: { margin: '2rem 0' },
  };

  const containerStyle: React.CSSProperties = {
    display: 'flex',
    alignItems: 'center',
    ...spacingStyles[spacing],
  };

  if (!text) {
    return (
      <div
        className={getElementClass('dividerLine')}
        style={{
          height: '1px',
          backgroundColor: cssVariables['--vault-color-border'],
          ...spacingStyles[spacing],
        }}
      />
    );
  }

  return (
    <div style={containerStyle}>
      <div
        className={[getElementClass('dividerLine'), lineClassName]
          .filter(Boolean)
          .join(' ')}
      />
      <span
        className={[getElementClass('dividerText'), textClassName]
          .filter(Boolean)
          .join(' ')}
      >
        {text}
      </span>
      <div
        className={[getElementClass('dividerLine'), lineClassName]
          .filter(Boolean)
          .join(' ')}
      />
    </div>
  );
}
