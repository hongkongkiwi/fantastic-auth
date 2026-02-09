# Vault React SDK Theming System

A Clerk-style enhanced theming system for the Vault React SDK that provides extensive customization options for all UI components.

## Overview

The theming system allows you to customize the appearance of Vault components through:

- **Base themes** (light, dark, neutral)
- **CSS variables** for colors, fonts, spacing, and more
- **Element class names** for targeted styling
- **Layout options** for social buttons and form organization

## Quick Start

### Global Theme Configuration

Wrap your app with `VaultProvider` and provide an `appearance` configuration:

```tsx
import { VaultProvider } from '@fantasticauth/react';

function App() {
  return (
    <VaultProvider
      config={{
        apiUrl: "https://api.vault.dev",
        tenantId: "my-tenant"
      }}
      appearance={{
        baseTheme: 'dark',
        variables: {
          colorPrimary: '#6366f1',
          borderRadius: '0.5rem',
        }
      }}
    >
      <YourApp />
    </VaultProvider>
  );
}
```

### Per-Component Theme Configuration

You can also configure themes per component:

```tsx
import { SignIn } from '@fantasticauth/react';

function LoginPage() {
  return (
    <SignIn
      appearance={{
        baseTheme: 'dark',
        variables: {
          colorPrimary: '#8b5cf6',
        },
        layout: {
          socialButtonsPlacement: 'top',
          socialButtonsVariant: 'iconButton',
        }
      }}
    />
  );
}
```

## Theme Configuration

### Base Themes

Choose from three built-in base themes:

```tsx
// Light theme (default)
appearance={{ baseTheme: 'light' }}

// Dark theme
appearance={{ baseTheme: 'dark' }}

// Neutral theme (gray palette)
appearance={{ baseTheme: 'neutral' }}
```

### CSS Variables

Customize the look and feel with CSS variables:

```tsx
appearance={{
  variables: {
    // Colors
    colorPrimary: '#6366f1',
    colorPrimaryHover: '#4f46e5',
    colorBackground: '#ffffff',
    colorInputBackground: '#ffffff',
    colorText: '#1a1a1a',
    colorTextSecondary: '#6b7280',
    colorDanger: '#ef4444',
    colorSuccess: '#22c55e',
    colorWarning: '#f59e0b',
    colorInputText: '#1a1a1a',
    colorInputBorder: '#d1d5db',
    
    // Typography
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
    fontFamilyButtons: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
    fontSize: '16px',
    fontWeight: 400,
    
    // Spacing & Layout
    borderRadius: '0.375rem',
    spacing: '1rem',
  }
}}
```

### Complete Variable Reference

| Variable | Description | Default (Light) |
|----------|-------------|-----------------|
| `colorPrimary` | Primary brand color | `#0066cc` |
| `colorPrimaryHover` | Primary color on hover | `#0052a3` |
| `colorBackground` | Page/app background | `#ffffff` |
| `colorInputBackground` | Input field background | `#ffffff` |
| `colorText` | Primary text color | `#1a1a1a` |
| `colorTextSecondary` | Secondary/muted text | `#6b7280` |
| `colorDanger` | Error/danger color | `#dc2626` |
| `colorSuccess` | Success color | `#16a34a` |
| `colorWarning` | Warning color | `#ca8a04` |
| `colorInputText` | Input text color | `#1a1a1a` |
| `colorInputBorder` | Input border color | `#d1d5db` |
| `fontFamily` | Base font family | System font stack |
| `fontFamilyButtons` | Button font family | System font stack |
| `fontSize` | Base font size | `16px` |
| `fontWeight` | Base font weight | `400` |
| `borderRadius` | Border radius | `0.375rem` |
| `spacing` | Base spacing unit | `1rem` |
| `colorShimmer` | Shimmer animation color | `rgba(0,0,0,0.05)` |
| `colorFocus` | Focus ring color | `rgba(0,102,204,0.25)` |
| `colorSurface` | Card/elevated surface | `#ffffff` |
| `colorBorder` | Divider/border color | `#e5e7eb` |
| `colorAvatarBackground` | Avatar placeholder bg | `#0066cc` |

### Layout Options

Configure the layout of form elements:

```tsx
appearance={{
  layout: {
    // Social buttons placement: 'top' or 'bottom'
    socialButtonsPlacement: 'bottom',
    
    // Social buttons style: 'iconButton', 'blockButton', or 'auto'
    socialButtonsVariant: 'blockButton',
    
    // Show optional fields by default
    showOptionalFields: true,
    
    // Enable shimmer loading effects
    shimmer: true,
    
    // Logo configuration
    logoUrl: 'https://example.com/logo.png',
    logoPlacement: 'inside', // 'inside', 'outside', or 'none'
  }
}}
```

### Element Class Names

Add custom CSS classes to specific elements:

```tsx
appearance={{
  elements: {
    root: 'my-custom-root',
    card: 'my-custom-card',
    formButtonPrimary: 'my-custom-button',
    formFieldInput: 'my-custom-input',
    headerTitle: 'my-custom-title',
    // ... and more
  }
}}
```

Available element names:

- `root` - Root container
- `card` - Card container
- `header` - Header container
- `headerTitle` - Header title
- `headerSubtitle` - Header subtitle
- `formButtonPrimary` - Primary button
- `formButtonSecondary` - Secondary button
- `formField` - Form field container
- `formFieldInput` - Input element
- `formFieldLabel` - Input label
- `formFieldError` - Error message
- `socialButtons` - Social buttons container
- `socialButtonsIconButton` - Social icon button
- `dividerLine` - Divider line
- `dividerText` - Divider text
- `alert` - Alert container
- `alertError` - Error alert
- `alertSuccess` - Success alert
- `alertWarning` - Warning alert
- `spinner` - Loading spinner
- `userButton` - User button container
- `userButtonTrigger` - User button trigger
- `userButtonPopover` - User button popover
- `userButtonPopoverCard` - User button popover card
- `avatarBox` - Avatar placeholder
- `menuItem` - Menu item
- `menuList` - Menu list

### Custom CSS

Add custom CSS that gets injected with the theme:

```tsx
appearance={{
  appendCss: `
    .my-custom-button {
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    
    .my-custom-card {
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
    }
  `
}}
```

## Theme Provider

For advanced use cases, you can use the `ThemeProvider` directly:

```tsx
import { ThemeProvider, useTheme } from '@fantasticauth/react';

function ThemedApp() {
  return (
    <ThemeProvider
      appearance={{
        baseTheme: 'dark',
        variables: { colorPrimary: '#6366f1' }
      }}
    >
      <YourComponents />
    </ThemeProvider>
  );
}

function CustomComponent() {
  const { theme, cssVariables, getElementClass, isDark } = useTheme();
  
  return (
    <div className={getElementClass('root')}>
      <button className={getElementClass('formButtonPrimary')}>
        Custom Button
      </button>
    </div>
  );
}
```

## UI Components

The theming system includes a set of themed UI components that you can use to build custom interfaces:

```tsx
import {
  Button,
  Input,
  Card,
  CardHeader,
  CardContent,
  Divider,
  Alert,
  Spinner,
  SocialButton,
} from '@fantasticauth/react';

function CustomForm() {
  return (
    <Card>
      <CardHeader title="Custom Form" />
      <CardContent>
        <Input label="Email" type="email" />
        <Input label="Password" type="password" />
        <Button>Submit</Button>
      </CardContent>
    </Card>
  );
}
```

### Button

```tsx
<Button variant="primary" size="md" isLoading={false}>
  Click me
</Button>
```

Props:
- `variant`: 'primary' | 'secondary' | 'ghost'
- `size`: 'sm' | 'md' | 'lg'
- `isLoading`: boolean
- `loadingText`: string
- `fullWidth`: boolean

### Input

```tsx
<Input
  label="Email"
  type="email"
  error="Invalid email"
  helperText="We'll never share your email"
/>
```

Props:
- `label`: string
- `error`: string
- `helperText`: string
- `size`: 'sm' | 'md' | 'lg'

### Card

```tsx
<Card padding="md" width="md" centered>
  <CardHeader title="Title" subtitle="Subtitle" />
  <CardContent>Content here</CardContent>
  <CardFooter>Footer here</CardFooter>
</Card>
```

### Alert

```tsx
<Alert variant="error" title="Error">
  Something went wrong
</Alert>
```

Props:
- `variant`: 'error' | 'success' | 'warning' | 'info'
- `title`: string
- `showIcon`: boolean
- `onDismiss`: () => void

### SocialButton

```tsx
<SocialButton
  provider="google"
  variant="block"
  onClick={() => {}}
/>
```

Props:
- `provider`: 'google' | 'github' | 'microsoft' | 'apple' | 'facebook' | 'twitter'
- `variant`: 'block' | 'icon'

## CSS Variables Output

The theme system generates CSS custom properties that are applied to the root element:

```css
.vault-root {
  --vault-color-primary: #6366f1;
  --vault-color-primary-hover: #4f46e5;
  --vault-color-background: #ffffff;
  --vault-color-input-background: #ffffff;
  --vault-color-text: #1a1a1a;
  --vault-color-text-secondary: #6b7280;
  --vault-color-danger: #ef4444;
  --vault-color-success: #22c55e;
  --vault-color-warning: #f59e0b;
  --vault-color-input-text: #1a1a1a;
  --vault-color-input-border: #d1d5db;
  --vault-font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  --vault-font-family-buttons: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  --vault-font-size: 16px;
  --vault-font-weight: 400;
  --vault-border-radius: 0.375rem;
  --vault-spacing: 1rem;
  --vault-color-shimmer: rgba(0, 0, 0, 0.05);
  --vault-color-focus: rgba(99, 102, 241, 0.25);
  --vault-color-surface: #ffffff;
  --vault-color-border: #e5e7eb;
  --vault-color-avatar-background: #6366f1;
}
```

You can use these variables in your own CSS for consistent theming:

```css
.my-custom-element {
  color: var(--vault-color-primary);
  background-color: var(--vault-color-background);
  border-radius: var(--vault-border-radius);
}
```

## Examples

### Dark Mode with Custom Colors

```tsx
<SignIn
  appearance={{
    baseTheme: 'dark',
    variables: {
      colorPrimary: '#a855f7',
      colorPrimaryHover: '#9333ea',
      borderRadius: '0.75rem',
    }
  }}
/>
```

### Minimal Design

```tsx
<SignIn
  appearance={{
    baseTheme: 'neutral',
    variables: {
      borderRadius: '0',
      spacing: '0.75rem',
    },
    layout: {
      socialButtonsVariant: 'iconButton',
    }
  }}
/>
```

### With Custom CSS Classes

```tsx
<SignIn
  appearance={{
    elements: {
      root: 'auth-container',
      card: 'auth-card',
      formButtonPrimary: 'btn-primary',
    },
    appendCss: `
      .auth-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
      }
      .btn-primary {
        background: rgba(255, 255, 255, 0.2);
        backdrop-filter: blur(10px);
      }
    `
  }}
/>
```

### Custom Logo

```tsx
<SignIn
  appearance={{
    layout: {
      logoUrl: 'https://myapp.com/logo.svg',
      logoPlacement: 'inside',
    }
  }}
/>
```

## Migration from Legacy Appearance

The new theming system is backward compatible. The old `theme` property still works:

```tsx
// Legacy (still works)
appearance={{
  theme: 'dark',
  variables: { colorPrimary: '#ff0000' }
}}

// New (recommended)
appearance={{
  baseTheme: 'dark',
  variables: { colorPrimary: '#ff0000' },
  layout: { socialButtonsPlacement: 'top' }
}}
```

## TypeScript Support

All theme types are exported:

```tsx
import type {
  Appearance,
  ThemeVariables,
  ElementStyles,
  LayoutOptions,
  Theme,
} from '@fantasticauth/react';
```
