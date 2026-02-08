/**
 * Vault React UI Styles
 * 
 * Utility functions for working with themes and styles.
 */

import type { Theme, ThemeVariables } from '../types';

/**
 * Apply CSS variables for custom theming
 */
export function applyThemeVariables(
  element: HTMLElement,
  variables: ThemeVariables
): void {
  const cssVars: Record<keyof ThemeVariables, string> = {
    primary: '--vault-primary',
    primaryHover: '--vault-primary-hover',
    primaryActive: '--vault-primary-active',
    error: '--vault-error',
    success: '--vault-success',
    warning: '--vault-warning',
    background: '--vault-background',
    surface: '--vault-surface',
    text: '--vault-text',
    textMuted: '--vault-text-muted',
    border: '--vault-border',
    borderRadius: '--vault-border-radius-md',
    fontFamily: '--vault-font-family',
    fontSize: '--vault-font-size-md',
    spacing: '--vault-spacing-md',
  };

  Object.entries(variables).forEach(([key, value]) => {
    const cssVar = cssVars[key as keyof ThemeVariables];
    if (cssVar && value) {
      element.style.setProperty(cssVar, value);
    }
  });
}

/**
 * Get theme class name
 */
export function getThemeClass(theme: Theme): string {
  switch (theme) {
    case 'dark':
      return 'vault-dark';
    case 'auto':
      return 'vault-auto';
    case 'light':
    default:
      return '';
  }
}

/**
 * Combine class names
 */
export function classNames(...classes: (string | undefined | null | false)[]): string {
  return classes.filter(Boolean).join(' ');
}

/**
 * Generate CSS for a custom theme
 */
export function generateCustomThemeCSS(variables: ThemeVariables): string {
  const cssVars = Object.entries(variables)
    .filter(([, value]) => value !== undefined)
    .map(([key, value]) => {
      const cssVarName = `--vault-${key.replace(/[A-Z]/g, (m) => `-${m.toLowerCase()}`)}`;
      return `  ${cssVarName}: ${value};`;
    })
    .join('\n');

  return `:root {\n${cssVars}\n}`;
}
