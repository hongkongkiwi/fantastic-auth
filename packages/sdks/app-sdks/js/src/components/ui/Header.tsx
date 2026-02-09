/**
 * Header Component
 *
 * Themed header component with title and subtitle.
 */

import React from 'react';
import { useTheme } from '../../theme';

// ============================================================================
// Types
// ============================================================================

export interface HeaderProps {
  /** Header title */
  title?: string;
  /** Header subtitle */
  subtitle?: string;
  /** Show logo */
  showLogo?: boolean;
  /** Custom logo URL (overrides layout config) */
  logoUrl?: string;
  /** Logo element (overrides URL) */
  logo?: React.ReactNode;
  /** Header alignment */
  align?: 'left' | 'center' | 'right';
  /** Custom title class name */
  titleClassName?: string;
  /** Custom subtitle class name */
  subtitleClassName?: string;
  /** Children to render after title/subtitle */
  children?: React.ReactNode;
}

// ============================================================================
// Component
// ============================================================================

export function Header({
  title,
  subtitle,
  showLogo,
  logoUrl,
  logo,
  align = 'center',
  titleClassName,
  subtitleClassName,
  children,
}: HeaderProps) {
  const { getElementClass, appearance } = useTheme();
  const layoutLogoUrl = logoUrl || appearance.layout?.logoUrl;
  const shouldShowLogo = showLogo && (logo || layoutLogoUrl);

  const alignStyles: Record<string, React.CSSProperties> = {
    left: { textAlign: 'left' },
    center: { textAlign: 'center' },
    right: { textAlign: 'right' },
  };

  return (
    <header
      className={getElementClass('header')}
      style={{
        padding: '1.5rem 1.5rem 0.5rem',
        ...alignStyles[align],
      }}
    >
      {shouldShowLogo && (
        <div style={{ marginBottom: '1rem' }}>
          {logo || (
            <img
              src={layoutLogoUrl}
              alt="Logo"
              style={{ height: '40px', width: 'auto' }}
            />
          )}
        </div>
      )}
      {title && (
        <h1
          className={[getElementClass('headerTitle'), titleClassName]
            .filter(Boolean)
            .join(' ')}
          style={{ margin: '0 0 0.5rem' }}
        >
          {title}
        </h1>
      )}
      {subtitle && (
        <p
          className={[getElementClass('headerSubtitle'), subtitleClassName]
            .filter(Boolean)
            .join(' ')}
          style={{ margin: 0 }}
        >
          {subtitle}
        </p>
      )}
      {children}
    </header>
  );
}
