/**
 * Theme Utilities
 *
 * Helper functions for theme manipulation and CSS generation.
 */

import {
  Theme,
  Appearance,
  ThemeVariables,
  ElementStyles,
  LayoutOptions,
} from './types';
import {
  lightTheme,
  darkTheme,
  neutralTheme,
  defaultElementStyles,
  defaultLayoutOptions,
} from './defaults';

// ============================================================================
// Theme Merging
// ============================================================================

/**
 * Merge appearance configuration with base theme
 */
export function mergeThemes(base: Theme, appearance?: Appearance): Theme {
  if (!appearance) {
    return base;
  }

  // Determine base theme
  let resolvedBase = base;
  if (appearance.baseTheme) {
    switch (appearance.baseTheme) {
      case 'dark':
        resolvedBase = darkTheme;
        break;
      case 'neutral':
        resolvedBase = neutralTheme;
        break;
      case 'light':
      default:
        resolvedBase = lightTheme;
        break;
    }
  }

  // Merge variables
  const variables: ThemeVariables = {
    ...resolvedBase.variables,
    ...appearance.variables,
  };

  // Merge elements
  const elements: ElementStyles = {
    ...resolvedBase.elements,
    ...appearance.elements,
  };

  // Merge layout
  const layout: LayoutOptions = {
    ...resolvedBase.layout,
    ...appearance.layout,
  };

  return {
    ...resolvedBase,
    variables,
    elements,
    layout,
  };
}

// ============================================================================
// CSS Variable Generation
// ============================================================================

/**
 * Generate CSS custom properties from theme variables
 */
export function generateCSSVariables(vars: ThemeVariables): Record<string, string> {
  return {
    '--vault-color-primary': vars.colorPrimary,
    '--vault-color-primary-hover': vars.colorPrimaryHover,
    '--vault-color-background': vars.colorBackground,
    '--vault-color-input-background': vars.colorInputBackground,
    '--vault-color-text': vars.colorText,
    '--vault-color-text-secondary': vars.colorTextSecondary,
    '--vault-color-danger': vars.colorDanger,
    '--vault-color-success': vars.colorSuccess,
    '--vault-color-warning': vars.colorWarning,
    '--vault-color-input-text': vars.colorInputText,
    '--vault-color-input-border': vars.colorInputBorder,
    '--vault-font-family': vars.fontFamily,
    '--vault-font-family-buttons': vars.fontFamilyButtons,
    '--vault-font-size': vars.fontSize,
    '--vault-font-weight': String(vars.fontWeight),
    '--vault-border-radius': vars.borderRadius,
    '--vault-spacing': vars.spacing,
    '--vault-color-shimmer': vars.colorShimmer || 'rgba(0, 0, 0, 0.05)',
    '--vault-color-focus': vars.colorFocus || 'rgba(0, 102, 204, 0.25)',
    '--vault-color-surface': vars.colorSurface || vars.colorBackground,
    '--vault-color-border': vars.colorBorder || vars.colorInputBorder,
    '--vault-color-avatar-background': vars.colorAvatarBackground || vars.colorPrimary,
  };
}

/**
 * Convert CSS variables object to inline style string
 */
export function cssVariablesToStyle(vars: Record<string, string>): React.CSSProperties {
  return vars as unknown as React.CSSProperties;
}

/**
 * Generate CSS variable string for injection
 */
export function generateCSSVariableString(vars: ThemeVariables): string {
  const cssVars = generateCSSVariables(vars);
  return Object.entries(cssVars)
    .map(([key, value]) => `${key}: ${value};`)
    .join('\n  ');
}

// ============================================================================
// Element Style Utilities
// ============================================================================

/**
 * Create a combined class name for an element
 */
export function createElementStyles(
  elements: ElementStyles,
  elementName: keyof ElementStyles
): string {
  const baseClass = defaultElementStyles[elementName];
  const customClass = elements[elementName];
  
  if (customClass && customClass !== baseClass) {
    return `${baseClass} ${customClass}`;
  }
  
  return baseClass || '';
}

/**
 * Get all class names for an element as an array
 */
export function getElementClasses(
  elements: ElementStyles,
  elementName: keyof ElementStyles
): string[] {
  const className = createElementStyles(elements, elementName);
  return className.split(' ').filter(Boolean);
}

// ============================================================================
// Layout Utilities
// ============================================================================

/**
 * Get layout option with fallback
 */
export function getLayoutOption<K extends keyof LayoutOptions>(
  layout: Partial<LayoutOptions>,
  key: K,
  defaultValue?: LayoutOptions[K]
): LayoutOptions[K] {
  const value = layout[key];
  if (value !== undefined) {
    return value as LayoutOptions[K];
  }
  if (defaultValue !== undefined) {
    return defaultValue;
  }
  return defaultLayoutOptions[key];
}

// ============================================================================
// Style Application
// ============================================================================

/**
 * Apply CSS variables to a style object
 */
export function applyCSSVariables(
  baseStyle: React.CSSProperties,
  vars: Record<string, string>
): React.CSSProperties {
  return {
    ...baseStyle,
    ...vars,
  };
}

/**
 * Merge class names
 */
export function cx(...classes: (string | undefined | null | false)[]): string {
  return classes.filter(Boolean).join(' ');
}

// ============================================================================
// Base Styles (for components without custom class names)
// ============================================================================

export interface BaseComponentStyles {
  buttonPrimary: React.CSSProperties;
  buttonSecondary: React.CSSProperties;
  input: React.CSSProperties;
  label: React.CSSProperties;
  card: React.CSSProperties;
  alert: React.CSSProperties;
  alertError: React.CSSProperties;
  alertSuccess: React.CSSProperties;
  alertWarning: React.CSSProperties;
  spinner: React.CSSProperties;
}

/**
 * Generate base component styles from CSS variables
 */
export function generateBaseStyles(vars: Record<string, string>): BaseComponentStyles {
  return {
    buttonPrimary: {
      display: 'inline-flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '0.75rem 1rem',
      fontSize: vars['--vault-font-size'],
      fontWeight: 600,
      fontFamily: vars['--vault-font-family-buttons'],
      color: '#ffffff',
      backgroundColor: vars['--vault-color-primary'],
      border: 'none',
      borderRadius: vars['--vault-border-radius'],
      cursor: 'pointer',
      transition: 'background-color 0.15s ease-in-out, box-shadow 0.15s ease-in-out',
    },
    buttonSecondary: {
      display: 'inline-flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '0.75rem 1rem',
      fontSize: vars['--vault-font-size'],
      fontWeight: 500,
      fontFamily: vars['--vault-font-family-buttons'],
      color: vars['--vault-color-text'],
      backgroundColor: 'transparent',
      border: `1px solid ${vars['--vault-color-border']}`,
      borderRadius: vars['--vault-border-radius'],
      cursor: 'pointer',
      transition: 'background-color 0.15s ease-in-out',
    },
    input: {
      width: '100%',
      padding: '0.625rem 0.75rem',
      fontSize: vars['--vault-font-size'],
      fontFamily: vars['--vault-font-family'],
      color: vars['--vault-color-input-text'],
      backgroundColor: vars['--vault-color-input-background'],
      border: `1px solid ${vars['--vault-color-input-border']}`,
      borderRadius: vars['--vault-border-radius'],
      outline: 'none',
      transition: 'border-color 0.15s ease-in-out, box-shadow 0.15s ease-in-out',
    },
    label: {
      display: 'block',
      marginBottom: '0.375rem',
      fontSize: '0.875rem',
      fontWeight: 500,
      fontFamily: vars['--vault-font-family'],
      color: vars['--vault-color-text'],
    },
    card: {
      backgroundColor: vars['--vault-color-surface'],
      border: `1px solid ${vars['--vault-color-border']}`,
      borderRadius: '0.75rem',
      boxShadow: '0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06)',
      overflow: 'hidden',
    },
    alert: {
      padding: '0.75rem 1rem',
      borderRadius: vars['--vault-border-radius'],
      fontSize: '0.875rem',
      fontFamily: vars['--vault-font-family'],
    },
    alertError: {
      color: vars['--vault-color-danger'],
      backgroundColor: `${vars['--vault-color-danger']}15`,
      border: `1px solid ${vars['--vault-color-danger']}30`,
    },
    alertSuccess: {
      color: vars['--vault-color-success'],
      backgroundColor: `${vars['--vault-color-success']}15`,
      border: `1px solid ${vars['--vault-color-success']}30`,
    },
    alertWarning: {
      color: vars['--vault-color-warning'],
      backgroundColor: `${vars['--vault-color-warning']}15`,
      border: `1px solid ${vars['--vault-color-warning']}30`,
    },
    spinner: {
      width: '1.25rem',
      height: '1.25rem',
      border: `2px solid ${vars['--vault-color-border']}`,
      borderTopColor: vars['--vault-color-primary'],
      borderRadius: '50%',
      animation: 'vault-spin 1s linear infinite',
    },
  };
}
