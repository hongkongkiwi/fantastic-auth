/**
 * Theme Types
 *
 * Clerk-style theming system types for Vault React SDK.
 */

// ============================================================================
// Theme Variables
// ============================================================================

export interface ThemeVariables {
  /** Primary brand color */
  colorPrimary: string;
  /** Primary color on hover state */
  colorPrimaryHover: string;
  /** Page/app background color */
  colorBackground: string;
  /** Input field background color */
  colorInputBackground: string;
  /** Primary text color */
  colorText: string;
  /** Secondary/muted text color */
  colorTextSecondary: string;
  /** Error/danger color */
  colorDanger: string;
  /** Success color */
  colorSuccess: string;
  /** Warning color */
  colorWarning: string;
  /** Input text color */
  colorInputText: string;
  /** Input border color */
  colorInputBorder: string;
  /** Base font family */
  fontFamily: string;
  /** Font family for buttons */
  fontFamilyButtons: string;
  /** Base font size */
  fontSize: string;
  /** Base font weight */
  fontWeight: string | number;
  /** Border radius for components */
  borderRadius: string;
  /** Base spacing unit */
  spacing: string;
  /** Color for shimmer animation */
  colorShimmer?: string;
  /** Focus ring color */
  colorFocus?: string;
  /** Card/elevated surface background */
  colorSurface?: string;
  /** Divider/border color */
  colorBorder?: string;
  /** Avatar background color */
  colorAvatarBackground?: string;
}

// ============================================================================
// Element Styles
// ============================================================================

export interface ElementStyles {
  /** Primary form button styles */
  formButtonPrimary?: string;
  /** Secondary form button styles */
  formButtonSecondary?: string;
  /** Form field container styles */
  formField?: string;
  /** Form input styles */
  formFieldInput?: string;
  /** Form label styles */
  formFieldLabel?: string;
  /** Form error message styles */
  formFieldError?: string;
  /** Social buttons container */
  socialButtons?: string;
  /** Individual social button/icon styles */
  socialButtonsIconButton?: string;
  /** Root container styles */
  root?: string;
  /** Card container styles */
  card?: string;
  /** Header container styles */
  header?: string;
  /** Header title styles */
  headerTitle?: string;
  /** Header subtitle styles */
  headerSubtitle?: string;
  /** Divider line styles */
  dividerLine?: string;
  /** Divider text styles */
  dividerText?: string;
  /** Alert/notification styles */
  alert?: string;
  /** Alert error variant */
  alertError?: string;
  /** Alert success variant */
  alertSuccess?: string;
  /** Alert warning variant */
  alertWarning?: string;
  /** Spinner/loading styles */
  spinner?: string;
  /** User button styles */
  userButton?: string;
  /** User button popover styles */
  userButtonPopover?: string;
  /** User button popover card */
  userButtonPopoverCard?: string;
  /** User button trigger styles */
  userButtonTrigger?: string;
  /** Avatar placeholder styles */
  avatarBox?: string;
  /** Menu item styles */
  menuItem?: string;
  /** Menu list styles */
  menuList?: string;
}

// ============================================================================
// Layout Options
// ============================================================================

export interface LayoutOptions {
  /** Placement of social buttons relative to form */
  socialButtonsPlacement: 'top' | 'bottom';
  /** Visual variant for social buttons */
  socialButtonsVariant: 'iconButton' | 'blockButton' | 'auto';
  /** Whether to show optional fields by default */
  showOptionalFields: boolean;
  /** Enable shimmer loading effect */
  shimmer: boolean;
  /** Help page URL for support links */
  helpPageUrl?: string;
  /** Privacy page URL */
  privacyPageUrl?: string;
  /** Terms page URL */
  termsPageUrl?: string;
  /** Logo URL to display */
  logoUrl?: string;
  /** Logo placement */
  logoPlacement?: 'inside' | 'outside' | 'none';
  /** Enable animations */
  animations?: boolean;
}

// ============================================================================
// Appearance Configuration
// ============================================================================

export interface Appearance {
  /** Base theme to use */
  baseTheme?: 'light' | 'dark' | 'neutral' | 'auto';
  /** CSS variable overrides */
  variables?: Partial<ThemeVariables>;
  /** Element class name overrides */
  elements?: ElementStyles;
  /** Layout configuration */
  layout?: Partial<LayoutOptions>;
  /** Additional CSS to inject */
  appendCss?: string;
}

// ============================================================================
// Complete Theme
// ============================================================================

export interface Theme {
  /** Theme identifier */
  id: string;
  /** Theme name */
  name: string;
  /** CSS variables */
  variables: ThemeVariables;
  /** Element class names */
  elements: ElementStyles;
  /** Layout options */
  layout: LayoutOptions;
  /** Whether this is a dark theme */
  isDark: boolean;
}

// ============================================================================
// Theme Context
// ============================================================================

export interface ThemeContextValue {
  /** Current theme */
  theme: Theme;
  /** Current appearance configuration */
  appearance: Appearance;
  /** Generated CSS variables */
  cssVariables: Record<string, string>;
  /** Get element class names */
  getElementClass: (elementName: keyof ElementStyles) => string;
  /** Check if layout option is enabled */
  getLayoutOption: <K extends keyof LayoutOptions>(key: K) => LayoutOptions[K];
  /** Check if current theme is dark */
  isDark: boolean;
}

// ============================================================================
// Theme Provider Props
// ============================================================================

export interface ThemeProviderProps {
  /** Child components */
  children: React.ReactNode;
  /** Appearance configuration */
  appearance?: Appearance;
  /** Default theme (overrides baseTheme in appearance) */
  defaultTheme?: 'light' | 'dark' | 'neutral';
}
