# Pre-built Themes

Vault provides pre-built themes that you can use or customize.

## Light Theme

Default light theme:

```tsx
const lightTheme = {
  theme: 'light' as const,
  variables: {
    colorPrimary: '#0066cc',
    colorDanger: '#dc2626',
    colorSuccess: '#059669',
    colorBackground: '#ffffff',
    colorText: '#1f2937',
    borderRadius: '6px',
    fontSize: '16px',
  },
};
```

## Dark Theme

Dark theme for dark mode:

```tsx
const darkTheme = {
  theme: 'dark' as const,
  variables: {
    colorPrimary: '#3b82f6',
    colorDanger: '#ef4444',
    colorSuccess: '#10b981',
    colorBackground: '#111827',
    colorText: '#f9fafb',
    borderRadius: '6px',
    fontSize: '16px',
  },
};
```

## Modern Theme

A modern, rounded theme:

```tsx
const modernTheme = {
  theme: 'light' as const,
  variables: {
    colorPrimary: '#6366f1',
    colorDanger: '#ef4444',
    colorSuccess: '#10b981',
    borderRadius: '12px',
    fontSize: '16px',
    fontFamily: 'Inter, system-ui, sans-serif',
  },
};
```

## Minimal Theme

Clean, minimal theme:

```tsx
const minimalTheme = {
  theme: 'light' as const,
  variables: {
    colorPrimary: '#000000',
    colorDanger: '#dc2626',
    borderRadius: '0px',
    fontSize: '14px',
  },
};
```

## Usage

```tsx
<SignIn appearance={modernTheme} />
```

## See Also

- [Customization](./customization.md) - Custom theme creation
- [CSS Variables](./css-variables.md) - Variable reference
