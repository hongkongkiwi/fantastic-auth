/**
 * Default Themes
 *
 * Pre-defined light, dark, and neutral themes following Clerk's design system.
 */

import { Theme, ThemeVariables, ElementStyles, LayoutOptions } from './types';

// ============================================================================
// Base Font Stacks
// ============================================================================

const fontStack = {
  system: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
  mono: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
};

// ============================================================================
// Light Theme Variables
// ============================================================================

export const lightThemeVariables: ThemeVariables = {
  colorPrimary: '#0066cc',
  colorPrimaryHover: '#0052a3',
  colorBackground: '#ffffff',
  colorInputBackground: '#ffffff',
  colorText: '#1a1a1a',
  colorTextSecondary: '#6b7280',
  colorDanger: '#dc2626',
  colorSuccess: '#16a34a',
  colorWarning: '#ca8a04',
  colorInputText: '#1a1a1a',
  colorInputBorder: '#d1d5db',
  fontFamily: fontStack.system,
  fontFamilyButtons: fontStack.system,
  fontSize: '16px',
  fontWeight: 400,
  borderRadius: '0.375rem',
  spacing: '1rem',
  colorShimmer: 'rgba(0, 0, 0, 0.05)',
  colorFocus: 'rgba(0, 102, 204, 0.25)',
  colorSurface: '#ffffff',
  colorBorder: '#e5e7eb',
  colorAvatarBackground: '#0066cc',
};

// ============================================================================
// Dark Theme Variables
// ============================================================================

export const darkThemeVariables: ThemeVariables = {
  colorPrimary: '#3b82f6',
  colorPrimaryHover: '#2563eb',
  colorBackground: '#0f0f10',
  colorInputBackground: '#1a1a1a',
  colorText: '#f9fafb',
  colorTextSecondary: '#9ca3af',
  colorDanger: '#ef4444',
  colorSuccess: '#22c55e',
  colorWarning: '#eab308',
  colorInputText: '#f9fafb',
  colorInputBorder: '#374151',
  fontFamily: fontStack.system,
  fontFamilyButtons: fontStack.system,
  fontSize: '16px',
  fontWeight: 400,
  borderRadius: '0.375rem',
  spacing: '1rem',
  colorShimmer: 'rgba(255, 255, 255, 0.05)',
  colorFocus: 'rgba(59, 130, 246, 0.25)',
  colorSurface: '#1a1a1a',
  colorBorder: '#374151',
  colorAvatarBackground: '#3b82f6',
};

// ============================================================================
// Neutral Theme Variables
// ============================================================================

export const neutralThemeVariables: ThemeVariables = {
  colorPrimary: '#6b7280',
  colorPrimaryHover: '#4b5563',
  colorBackground: '#f9fafb',
  colorInputBackground: '#ffffff',
  colorText: '#111827',
  colorTextSecondary: '#6b7280',
  colorDanger: '#ef4444',
  colorSuccess: '#10b981',
  colorWarning: '#f59e0b',
  colorInputText: '#111827',
  colorInputBorder: '#d1d5db',
  fontFamily: fontStack.system,
  fontFamilyButtons: fontStack.system,
  fontSize: '16px',
  fontWeight: 400,
  borderRadius: '0.5rem',
  spacing: '1rem',
  colorShimmer: 'rgba(0, 0, 0, 0.03)',
  colorFocus: 'rgba(107, 114, 128, 0.25)',
  colorSurface: '#ffffff',
  colorBorder: '#e5e7eb',
  colorAvatarBackground: '#6b7280',
};

// ============================================================================
// Default Element Styles (CSS class names)
// ============================================================================

export const defaultElementStyles: ElementStyles = {
  root: 'vault-root',
  card: 'vault-card',
  header: 'vault-header',
  headerTitle: 'vault-header-title',
  headerSubtitle: 'vault-header-subtitle',
  formButtonPrimary: 'vault-form-button-primary',
  formButtonSecondary: 'vault-form-button-secondary',
  formField: 'vault-form-field',
  formFieldInput: 'vault-form-field-input',
  formFieldLabel: 'vault-form-field-label',
  formFieldError: 'vault-form-field-error',
  socialButtons: 'vault-social-buttons',
  socialButtonsIconButton: 'vault-social-buttons-icon-button',
  dividerLine: 'vault-divider-line',
  dividerText: 'vault-divider-text',
  alert: 'vault-alert',
  alertError: 'vault-alert-error',
  alertSuccess: 'vault-alert-success',
  alertWarning: 'vault-alert-warning',
  spinner: 'vault-spinner',
  userButton: 'vault-user-button',
  userButtonPopover: 'vault-user-button-popover',
  userButtonPopoverCard: 'vault-user-button-popover-card',
  userButtonTrigger: 'vault-user-button-trigger',
  avatarBox: 'vault-avatar-box',
  menuItem: 'vault-menu-item',
  menuList: 'vault-menu-list',
};

// ============================================================================
// Default Layout Options
// ============================================================================

export const defaultLayoutOptions: LayoutOptions = {
  socialButtonsPlacement: 'bottom',
  socialButtonsVariant: 'blockButton',
  showOptionalFields: true,
  shimmer: true,
  animations: true,
  logoPlacement: 'inside',
};

// ============================================================================
// Complete Themes
// ============================================================================

export const lightTheme: Theme = {
  id: 'light',
  name: 'Light',
  variables: lightThemeVariables,
  elements: defaultElementStyles,
  layout: defaultLayoutOptions,
  isDark: false,
};

export const darkTheme: Theme = {
  id: 'dark',
  name: 'Dark',
  variables: darkThemeVariables,
  elements: defaultElementStyles,
  layout: defaultLayoutOptions,
  isDark: true,
};

export const neutralTheme: Theme = {
  id: 'neutral',
  name: 'Neutral',
  variables: neutralThemeVariables,
  elements: defaultElementStyles,
  layout: defaultLayoutOptions,
  isDark: false,
};

// ============================================================================
// Theme Map
// ============================================================================

export const themes: Record<string, Theme> = {
  light: lightTheme,
  dark: darkTheme,
  neutral: neutralTheme,
};

/**
 * Get a theme by ID
 */
export function getTheme(themeId: string): Theme {
  return themes[themeId] || lightTheme;
}
