/**
 * Vault Theme System
 *
 * Clerk-style theming system for Vault React SDK.
 *
 * @example
 * ```tsx
 * import { ThemeProvider, useTheme, lightTheme } from '@vault/react/theme';
 *
 * function App() {
 *   return (
 *     <ThemeProvider
 *       appearance={{
 *         baseTheme: 'dark',
 *         variables: {
 *           colorPrimary: '#ff0000',
 *         },
 *       }}
 *     >
 *       <YourApp />
 *     </ThemeProvider>
 *   );
 * }
 * ```
 */

// ============================================================================
// Types
// ============================================================================

export type {
  ThemeVariables,
  ElementStyles,
  LayoutOptions,
  Appearance,
  Theme,
  ThemeContextValue,
  ThemeProviderProps,
} from './types';

// ============================================================================
// Theme Provider & Hook
// ============================================================================

export {
  ThemeProvider,
  useTheme,
  withTheme,
  ThemeContext,
} from './ThemeProvider';

// ============================================================================
// Default Themes
// ============================================================================

export {
  lightTheme,
  darkTheme,
  neutralTheme,
  themes,
  getTheme,
  lightThemeVariables,
  darkThemeVariables,
  neutralThemeVariables,
  defaultElementStyles,
  defaultLayoutOptions,
} from './defaults';

// ============================================================================
// Utilities
// ============================================================================

export {
  mergeThemes,
  generateCSSVariables,
  generateCSSVariableString,
  cssVariablesToStyle,
  createElementStyles,
  getElementClasses,
  getLayoutOption,
  applyCSSVariables,
  cx,
  generateBaseStyles,
} from './utils';

export type { BaseComponentStyles } from './utils';
