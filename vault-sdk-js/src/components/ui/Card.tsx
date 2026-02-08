/**
 * Card Component
 *
 * Themed card container component.
 */

import React, { forwardRef } from 'react';
import { useTheme } from '../../theme';

// ============================================================================
// Types
// ============================================================================

export interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  /** Card padding */
  padding?: 'none' | 'sm' | 'md' | 'lg';
  /** Card width */
  width?: 'auto' | 'sm' | 'md' | 'lg' | 'full';
  /** Center the card horizontally */
  centered?: boolean;
}

// ============================================================================
// Component
// ============================================================================

export const Card = forwardRef<HTMLDivElement, CardProps>(
  (
    {
      children,
      padding = 'md',
      width = 'md',
      centered = false,
      className,
      style,
      ...props
    },
    ref
  ) => {
    const { getElementClass } = useTheme();

    // Padding styles
    const paddingStyles: Record<string, React.CSSProperties> = {
      none: { padding: 0 },
      sm: { padding: '1rem' },
      md: { padding: '1.5rem' },
      lg: { padding: '2rem' },
    };

    // Width styles
    const widthStyles: Record<string, React.CSSProperties> = {
      auto: {},
      sm: { maxWidth: '320px' },
      md: { maxWidth: '400px' },
      lg: { maxWidth: '480px' },
      full: { maxWidth: '100%' },
    };

    const cardStyle: React.CSSProperties = {
      ...paddingStyles[padding],
      ...widthStyles[width],
      margin: centered ? '0 auto' : undefined,
      ...style,
    };

    return (
      <div
        ref={ref}
        className={[getElementClass('card'), 'vault-root', className]
          .filter(Boolean)
          .join(' ')}
        style={cardStyle}
        {...props}
      >
        {children}
      </div>
    );
  }
);

Card.displayName = 'Card';

// ============================================================================
// Card Header
// ============================================================================

export interface CardHeaderProps extends React.HTMLAttributes<HTMLDivElement> {
  /** Card title */
  title?: string;
  /** Card subtitle */
  subtitle?: string;
  /** Show logo */
  showLogo?: boolean;
  /** Logo URL */
  logoUrl?: string;
}

export const CardHeader = forwardRef<HTMLDivElement, CardHeaderProps>(
  ({ title, subtitle, showLogo, logoUrl, className, style, children, ...props }, ref) => {
    const { getElementClass, appearance } = useTheme();
    const layoutLogoUrl = logoUrl || appearance.layout?.logoUrl;
    const shouldShowLogo = showLogo && layoutLogoUrl;

    return (
      <div
        ref={ref}
        className={[getElementClass('header'), className].filter(Boolean).join(' ')}
        style={style}
        {...props}
      >
        {shouldShowLogo && (
          <div style={{ marginBottom: '1rem' }}>
            <img
              src={layoutLogoUrl}
              alt="Logo"
              style={{ height: '40px', width: 'auto' }}
            />
          </div>
        )}
        {title && (
          <h1 className={getElementClass('headerTitle')} style={{ margin: 0 }}>
            {title}
          </h1>
        )}
        {subtitle && (
          <p className={getElementClass('headerSubtitle')} style={{ margin: '0.5rem 0 0' }}>
            {subtitle}
          </p>
        )}
        {children}
      </div>
    );
  }
);

CardHeader.displayName = 'CardHeader';

// ============================================================================
// Card Content
// ============================================================================

export interface CardContentProps extends React.HTMLAttributes<HTMLDivElement> {
  /** Content spacing */
  spacing?: 'none' | 'sm' | 'md' | 'lg';
}

export const CardContent = forwardRef<HTMLDivElement, CardContentProps>(
  ({ children, spacing = 'md', className, style, ...props }, ref) => {
    const spacingStyles: Record<string, React.CSSProperties> = {
      none: {},
      sm: { display: 'flex', flexDirection: 'column', gap: '0.75rem' },
      md: { display: 'flex', flexDirection: 'column', gap: '1rem' },
      lg: { display: 'flex', flexDirection: 'column', gap: '1.5rem' },
    };

    return (
      <div
        ref={ref}
        className={className}
        style={{
          ...spacingStyles[spacing],
          ...style,
        }}
        {...props}
      >
        {children}
      </div>
    );
  }
);

CardContent.displayName = 'CardContent';

// ============================================================================
// Card Footer
// ============================================================================

export interface CardFooterProps extends React.HTMLAttributes<HTMLDivElement> {
  /** Footer alignment */
  align?: 'left' | 'center' | 'right';
}

export const CardFooter = forwardRef<HTMLDivElement, CardFooterProps>(
  ({ children, align = 'center', className, style, ...props }, ref) => {
    const alignStyles: Record<string, React.CSSProperties> = {
      left: { textAlign: 'left' },
      center: { textAlign: 'center' },
      right: { textAlign: 'right' },
    };

    const { cssVariables } = useTheme();

    return (
      <div
        ref={ref}
        className={className}
        style={{
          marginTop: '1.5rem',
          paddingTop: '1.5rem',
          borderTop: `1px solid ${cssVariables['--vault-color-border']}`,
          ...alignStyles[align],
          ...style,
        }}
        {...props}
      >
        {children}
      </div>
    );
  }
);

CardFooter.displayName = 'CardFooter';
