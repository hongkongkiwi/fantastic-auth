/**
 * Theme Provider
 *
 * React context provider for Vault theming system.
 */

import React, {
  createContext,
  useContext,
  useMemo,
} from 'react';
import {
  Theme,
  ThemeContextValue,
  ThemeProviderProps,
  ElementStyles,
  LayoutOptions,
} from './types';
import {
  lightTheme,
  darkTheme,
  neutralTheme,
} from './defaults';
import {
  mergeThemes,
  generateCSSVariables,
  createElementStyles,
} from './utils';

// ============================================================================
// Context Creation
// ============================================================================

const ThemeContext = createContext<ThemeContextValue | null>(null);

// ============================================================================
// Global Styles Component
// ============================================================================

interface GlobalStylesProps {
  theme: Theme;
  appendCss?: string;
}

function GlobalStyles({ theme, appendCss }: GlobalStylesProps) {
  const cssVariables = useMemo(() => generateCSSVariables(theme.variables), [theme.variables]);
  
  const styleContent = useMemo(() => {
    const vars = Object.entries(cssVariables)
      .map(([key, value]) => `  ${key}: ${value};`)
      .join('\n');

    const baseStyles = `
/* Vault Theme Variables */
.vault-root {
${vars}
}

/* Vault Base Styles */
.vault-card {
  background-color: var(--vault-color-surface);
  border: 1px solid var(--vault-color-border);
  border-radius: 0.75rem;
  box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06);
  overflow: hidden;
}

.vault-header {
  padding: 1.5rem 1.5rem 0.5rem;
  text-align: center;
}

.vault-header-title {
  margin: 0 0 0.5rem;
  font-size: 1.5rem;
  font-weight: 600;
  font-family: var(--vault-font-family);
  color: var(--vault-color-text);
}

.vault-header-subtitle {
  margin: 0;
  font-size: 0.875rem;
  font-family: var(--vault-font-family);
  color: var(--vault-color-text-secondary);
}

.vault-form-field {
  margin-bottom: 1rem;
}

.vault-form-field-label {
  display: block;
  margin-bottom: 0.375rem;
  font-size: 0.875rem;
  font-weight: 500;
  font-family: var(--vault-font-family);
  color: var(--vault-color-text);
}

.vault-form-field-input {
  width: 100%;
  padding: 0.625rem 0.75rem;
  font-size: var(--vault-font-size);
  font-family: var(--vault-font-family);
  color: var(--vault-color-input-text);
  background-color: var(--vault-color-input-background);
  border: 1px solid var(--vault-color-input-border);
  border-radius: var(--vault-border-radius);
  outline: none;
  transition: border-color 0.15s ease-in-out, box-shadow 0.15s ease-in-out;
  box-sizing: border-box;
}

.vault-form-field-input:focus {
  border-color: var(--vault-color-primary);
  box-shadow: 0 0 0 3px var(--vault-color-focus);
}

.vault-form-field-input:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.vault-form-field-error {
  display: block;
  margin-top: 0.375rem;
  font-size: 0.75rem;
  font-family: var(--vault-font-family);
  color: var(--vault-color-danger);
}

.vault-form-button-primary {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 100%;
  padding: 0.75rem 1rem;
  font-size: var(--vault-font-size);
  font-weight: 600;
  font-family: var(--vault-font-family-buttons);
  color: #ffffff;
  background-color: var(--vault-color-primary);
  border: none;
  border-radius: var(--vault-border-radius);
  cursor: pointer;
  transition: background-color 0.15s ease-in-out, box-shadow 0.15s ease-in-out;
  box-sizing: border-box;
}

.vault-form-button-primary:hover:not(:disabled) {
  background-color: var(--vault-color-primary-hover);
}

.vault-form-button-primary:focus {
  outline: none;
  box-shadow: 0 0 0 3px var(--vault-color-focus);
}

.vault-form-button-primary:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.vault-form-button-secondary {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 100%;
  padding: 0.75rem 1rem;
  font-size: var(--vault-font-size);
  font-weight: 500;
  font-family: var(--vault-font-family-buttons);
  color: var(--vault-color-text);
  background-color: transparent;
  border: 1px solid var(--vault-color-border);
  border-radius: var(--vault-border-radius);
  cursor: pointer;
  transition: background-color 0.15s ease-in-out;
  box-sizing: border-box;
}

.vault-form-button-secondary:hover:not(:disabled) {
  background-color: var(--vault-color-shimmer);
}

.vault-form-button-secondary:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.vault-social-buttons {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.vault-social-buttons-icon-button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 2.75rem;
  height: 2.75rem;
  padding: 0;
  background-color: var(--vault-color-surface);
  border: 1px solid var(--vault-color-border);
  border-radius: var(--vault-border-radius);
  cursor: pointer;
  transition: background-color 0.15s ease-in-out, border-color 0.15s ease-in-out;
}

.vault-social-buttons-icon-button:hover:not(:disabled) {
  background-color: var(--vault-color-shimmer);
  border-color: var(--vault-color-input-border);
}

.vault-divider-line {
  flex: 1;
  height: 1px;
  background-color: var(--vault-color-border);
}

.vault-divider-text {
  padding: 0 1rem;
  font-size: 0.875rem;
  font-family: var(--vault-font-family);
  color: var(--vault-color-text-secondary);
}

.vault-alert {
  padding: 0.75rem 1rem;
  border-radius: var(--vault-border-radius);
  font-size: 0.875rem;
  font-family: var(--vault-font-family);
}

.vault-alert-error {
  color: var(--vault-color-danger);
  background-color: color-mix(in srgb, var(--vault-color-danger) 10%, transparent);
  border: 1px solid color-mix(in srgb, var(--vault-color-danger) 20%, transparent);
}

.vault-alert-success {
  color: var(--vault-color-success);
  background-color: color-mix(in srgb, var(--vault-color-success) 10%, transparent);
  border: 1px solid color-mix(in srgb, var(--vault-color-success) 20%, transparent);
}

.vault-alert-warning {
  color: var(--vault-color-warning);
  background-color: color-mix(in srgb, var(--vault-color-warning) 10%, transparent);
  border: 1px solid color-mix(in srgb, var(--vault-color-warning) 20%, transparent);
}

.vault-spinner {
  width: 1.25rem;
  height: 1.25rem;
  border: 2px solid var(--vault-color-border);
  border-top-color: var(--vault-color-primary);
  border-radius: 50%;
  animation: vault-spin 1s linear infinite;
}

@keyframes vault-spin {
  to {
    transform: rotate(360deg);
  }
}

.vault-shimmer {
  background: linear-gradient(
    90deg,
    var(--vault-color-shimmer) 0%,
    color-mix(in srgb, var(--vault-color-shimmer) 50%, transparent) 50%,
    var(--vault-color-shimmer) 100%
  );
  background-size: 200% 100%;
  animation: vault-shimmer 1.5s infinite;
}

@keyframes vault-shimmer {
  0% {
    background-position: 200% 0;
  }
  100% {
    background-position: -200% 0;
  }
}

.vault-user-button {
  position: relative;
  display: inline-block;
}

.vault-user-button-trigger {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.375rem 0.75rem;
  background: transparent;
  border: 1px solid var(--vault-color-border);
  border-radius: var(--vault-border-radius);
  cursor: pointer;
  font-size: 0.875rem;
  font-family: var(--vault-font-family);
  color: var(--vault-color-text);
  transition: background-color 0.15s ease-in-out;
}

.vault-user-button-trigger:hover {
  background-color: var(--vault-color-shimmer);
}

.vault-user-button-popover {
  position: absolute;
  top: calc(100% + 0.5rem);
  right: 0;
  min-width: 220px;
  z-index: 1000;
}

.vault-user-button-popover-card {
  background-color: var(--vault-color-surface);
  border: 1px solid var(--vault-color-border);
  border-radius: var(--vault-border-radius);
  box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
  overflow: hidden;
}

.vault-avatar-box {
  width: 2rem;
  height: 2rem;
  border-radius: 50%;
  background-color: var(--vault-color-avatar-background);
  color: #ffffff;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 0.875rem;
  font-weight: 600;
  font-family: var(--vault-font-family);
}

.vault-menu-list {
  list-style: none;
  margin: 0;
  padding: 0;
}

.vault-menu-item {
  display: flex;
  align-items: center;
  width: 100%;
  padding: 0.625rem 1rem;
  font-size: 0.875rem;
  font-family: var(--vault-font-family);
  color: var(--vault-color-text);
  background: transparent;
  border: none;
  cursor: pointer;
  text-align: left;
  transition: background-color 0.15s ease-in-out;
}

.vault-menu-item:hover {
  background-color: var(--vault-color-shimmer);
}
`;

    const customStyles = appendCss || '';

    return baseStyles + '\n' + customStyles;
  }, [cssVariables, appendCss]);

  return <style>{styleContent}</style>;
}

// ============================================================================
// Theme Provider Component
// ============================================================================

export function ThemeProvider({
  children,
  appearance = {},
  defaultTheme,
}: ThemeProviderProps) {
  // Determine base theme
  const baseTheme = useMemo(() => {
    const themeId = defaultTheme || appearance.baseTheme || 'light';
    switch (themeId) {
      case 'dark':
        return darkTheme;
      case 'neutral':
        return neutralTheme;
      case 'light':
      default:
        return lightTheme;
    }
  }, [appearance.baseTheme, defaultTheme]);

  // Merge theme with appearance
  const theme = useMemo(() => {
    return mergeThemes(baseTheme, appearance);
  }, [baseTheme, appearance]);

  // Generate CSS variables
  const cssVariables = useMemo(() => {
    return generateCSSVariables(theme.variables);
  }, [theme.variables]);

  // Get element class helper
  const getElementClass = useMemo(() => {
    return (elementName: keyof ElementStyles): string => {
      return createElementStyles(theme.elements, elementName);
    };
  }, [theme.elements]);

  // Get layout option helper
  const getLayoutOption = useMemo(() => {
    return <K extends keyof LayoutOptions>(key: K): LayoutOptions[K] => {
      return getLayoutOptionHelper(theme.layout, key);
    };
  }, [theme.layout]);

  // Context value
  const value: ThemeContextValue = useMemo(
    () => ({
      theme,
      appearance,
      cssVariables,
      getElementClass,
      getLayoutOption,
      isDark: theme.isDark,
    }),
    [theme, appearance, cssVariables, getElementClass, getLayoutOption]
  );

  return (
    <ThemeContext.Provider value={value}>
      <GlobalStyles theme={theme} appendCss={appearance.appendCss} />
      {children}
    </ThemeContext.Provider>
  );
}

// Helper function for layout options
function getLayoutOptionHelper<K extends keyof LayoutOptions>(
  layout: Partial<LayoutOptions>,
  key: K
): LayoutOptions[K] {
  const value = layout[key];
  if (value !== undefined) {
    return value as LayoutOptions[K];
  }
  // Return defaults
  const defaults: LayoutOptions = {
    socialButtonsPlacement: 'bottom',
    socialButtonsVariant: 'blockButton',
    showOptionalFields: true,
    shimmer: true,
  };
  return defaults[key];
}

// ============================================================================
// useTheme Hook
// ============================================================================

export function useTheme(): ThemeContextValue {
  const context = useContext(ThemeContext);

  if (!context) {
    throw new Error('useTheme must be used within a ThemeProvider');
  }

  return context;
}

// ============================================================================
// withTheme HOC
// ============================================================================

export function withTheme<P extends object>(
  Component: React.ComponentType<P & { theme: ThemeContextValue }>
): React.FC<P> {
  return function WithThemeComponent(props: P) {
    const theme = useTheme();
    return <Component {...props} theme={theme} />;
  };
}

// Re-export context for advanced use cases
export { ThemeContext };
