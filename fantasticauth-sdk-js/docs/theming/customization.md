# Customizing Appearance

The Vault React SDK provides extensive theming capabilities to match your application's design.

## Overview

Customize components using the `appearance` prop:

```tsx
<SignIn
  appearance={{
    theme: 'light',
    variables: {
      colorPrimary: '#6366f1',
      borderRadius: '8px',
    },
  }}
/>
```

## Appearance Object

```tsx
interface Appearance {
  theme?: 'light' | 'dark' | 'auto';
  variables?: Record<string, string>;
  elements?: Record<string, React.CSSProperties>;
}
```

## Theme Selection

### Light Theme

```tsx
<SignIn appearance={{ theme: 'light' }} />
```

### Dark Theme

```tsx
<SignIn appearance={{ theme: 'dark' }} />
```

### Auto Theme

Automatically matches system preference:

```tsx
<SignIn appearance={{ theme: 'auto' }} />
```

## CSS Variables

Override default values using CSS variables:

```tsx
<SignIn
  appearance={{
    variables: {
      // Primary color
      colorPrimary: '#6366f1',
      
      // Danger/error color
      colorDanger: '#ef4444',
      
      // Success color
      colorSuccess: '#10b981',
      
      // Border radius
      borderRadius: '8px',
      
      // Font size
      fontSize: '16px',
      
      // Font family
      fontFamily: 'Inter, system-ui, sans-serif',
    },
  }}
/>
```

### Available Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `colorPrimary` | `#0066cc` | Primary brand color |
| `colorPrimaryHover` | `#0052a3` | Primary color on hover |
| `colorDanger` | `#dc2626` | Error/danger color |
| `colorSuccess` | `#059669` | Success color |
| `colorWarning` | `#d97706` | Warning color |
| `colorText` | `#1f2937` | Primary text color |
| `colorTextSecondary` | `#6b7280` | Secondary text color |
| `colorBackground` | `#ffffff` | Background color |
| `colorInputBackground` | `#ffffff` | Input background |
| `colorInputBorder` | `#d1d5db` | Input border color |
| `borderRadius` | `6px` | Border radius for elements |
| `fontSize` | `16px` | Base font size |
| `fontFamily` | System font | Font family |
| `spacingUnit` | `1rem` | Base spacing unit |

## Element Styling

Style individual elements directly:

```tsx
<SignIn
  appearance={{
    elements: {
      // Form container
      container: {
        maxWidth: '450px',
        padding: '2rem',
      },
      
      // Title
      title: {
        fontSize: '1.5rem',
        fontWeight: 700,
        marginBottom: '1.5rem',
      },
      
      // Input fields
      input: {
        borderWidth: '2px',
        padding: '0.75rem 1rem',
      },
      
      // Submit button
      button: {
        padding: '0.875rem 1.5rem',
        fontWeight: 600,
        textTransform: 'uppercase',
      },
      
      // Error messages
      error: {
        backgroundColor: '#fef2f2',
        borderLeft: '4px solid #ef4444',
        padding: '0.75rem 1rem',
      },
      
      // OAuth buttons
      oauthButton: {
        borderWidth: '1px',
        boxShadow: '0 1px 2px rgba(0,0,0,0.05)',
      },
      
      // Divider
      divider: {
        color: '#9ca3af',
        fontSize: '0.875rem',
      },
    },
  }}
/>
```

### Available Elements

| Element | Description |
|-----------|-------------|
| `container` | Outer container wrapper |
| `form` | Form element |
| `title` | Form title |
| `field` | Form field container |
| `label` | Field label |
| `input` | Text inputs |
| `button` | Submit/action buttons |
| `linkButton` | Text link buttons |
| `error` | Error messages |
| `success` | Success messages |
| `divider` | Divider between sections |
| `oauthContainer` | OAuth buttons container |
| `oauthButton` | Individual OAuth buttons |
| `avatar` | User avatar image |
| `avatarPlaceholder` | Avatar fallback |
| `menu` | Dropdown menu |
| `menuItem` | Menu items |

## Complete Theme Example

Create a consistent theme across all components:

```tsx
// theme/vault.ts
export const vaultTheme = {
  theme: 'light' as const,
  variables: {
    colorPrimary: '#6366f1',
    colorPrimaryHover: '#4f46e5',
    colorDanger: '#ef4444',
    colorSuccess: '#10b981',
    colorText: '#111827',
    colorTextSecondary: '#6b7280',
    borderRadius: '0.5rem',
    fontSize: '1rem',
    fontFamily: 'Inter, system-ui, sans-serif',
  },
  elements: {
    container: {
      maxWidth: '420px',
      margin: '0 auto',
    },
    button: {
      borderRadius: '0.5rem',
      fontWeight: 500,
    },
    input: {
      borderRadius: '0.5rem',
      borderWidth: '1px',
    },
  },
};

// Usage in components
import { vaultTheme } from './theme/vault';

<SignIn appearance={vaultTheme} />
<SignUp appearance={vaultTheme} />
<UserProfile appearance={vaultTheme} />
```

## Dark Mode Theme

Create a dark mode theme:

```tsx
const darkTheme = {
  theme: 'dark' as const,
  variables: {
    colorPrimary: '#818cf8',
    colorPrimaryHover: '#6366f1',
    colorDanger: '#f87171',
    colorSuccess: '#34d399',
    colorText: '#f9fafb',
    colorTextSecondary: '#9ca3af',
    colorBackground: '#111827',
    colorInputBackground: '#1f2937',
    colorInputBorder: '#374151',
    borderRadius: '0.5rem',
    fontSize: '1rem',
  },
};

<SignIn appearance={darkTheme} />
```

### Dynamic Theme Switching

```tsx
import { useState, useEffect } from 'react';

function App() {
  const [isDark, setIsDark] = useState(false);

  useEffect(() => {
    // Check system preference
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    setIsDark(prefersDark);
  }, []);

  const theme = {
    theme: isDark ? 'dark' : 'light',
    variables: {
      colorPrimary: '#6366f1',
      borderRadius: '0.5rem',
    },
  };

  return (
    <div className={isDark ? 'dark' : 'light'}>
      <button onClick={() => setIsDark(!isDark)}>
        Toggle {isDark ? 'Light' : 'Dark'} Mode
      </button>
      <SignIn appearance={theme} />
    </div>
  );
}
```

## Tailwind CSS Integration

Use Tailwind classes with the `className` prop:

```tsx
<SignIn
  className="max-w-md mx-auto p-6"
  appearance={{
    variables: {
      colorPrimary: '#6366f1',
      borderRadius: '0.5rem',
    },
  }}
/>
```

Or extend Tailwind configuration:

```js
// tailwind.config.js
module.exports = {
  theme: {
    extend: {
      colors: {
        vault: {
          primary: '#6366f1',
          danger: '#ef4444',
          success: '#10b981',
        },
      },
    },
  },
};
```

## CSS-in-JS Integration

### Styled Components

```tsx
import styled from 'styled-components';
import { SignIn } from '@vault/react';

const StyledSignIn = styled(SignIn)`
  max-width: 450px;
  margin: 2rem auto;
`;

// Or use appearance prop
<SignIn
  appearance={{
    elements: {
      button: {
        backgroundColor: '${props => props.theme.primary}',
      },
    },
  }}
/>
```

### Emotion

```tsx
/** @jsxImportSource @emotion/react */
import { css } from '@emotion/react';

const customStyles = css`
  max-width: 450px;
  margin: 0 auto;
`;

<div css={customStyles}>
  <SignIn appearance={theme} />
</div>
```

## Brand Customization

Match your brand colors:

```tsx
const brandTheme = {
  variables: {
    colorPrimary: '#your-brand-color',
    colorPrimaryHover: '#your-brand-color-dark',
    borderRadius: 'your-border-radius',
    fontFamily: 'your-font-family',
  },
};
```

## Accessibility

Ensure your theme maintains accessibility:

```tsx
const accessibleTheme = {
  variables: {
    // Ensure contrast ratio of at least 4.5:1
    colorPrimary: '#2563eb', // Good contrast on white
    colorText: '#1f2937',    // Good contrast on white
    
    // Focus indicators
    colorPrimaryHover: '#1d4ed8',
    
    // Error states (always visible)
    colorDanger: '#dc2626',
  },
};
```

## Responsive Design

Components are responsive by default. Use the `className` prop for additional breakpoints:

```tsx
<SignIn
  className="w-full max-w-sm md:max-w-md lg:max-w-lg"
  appearance={theme}
/>
```

## See Also

- [CSS Variables Reference](./css-variables.md) - Complete variable list
- [Themes](./themes.md) - Pre-built themes
- [Components](../components/README.md) - Component documentation
