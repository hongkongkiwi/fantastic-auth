# Theming Overview

The Vault React SDK provides comprehensive theming capabilities to match your application's design system.

## Quick Start

Customize components with the `appearance` prop:

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

## Theming Options

### 1. CSS Variables

Override default design tokens:

```tsx
<SignIn
  appearance={{
    variables: {
      colorPrimary: '#6366f1',
      colorDanger: '#ef4444',
      borderRadius: '12px',
      fontSize: '16px',
    },
  }}
/>
```

### 2. Element Styling

Style individual UI elements:

```tsx
<SignIn
  appearance={{
    elements: {
      button: { padding: '14px 28px' },
      input: { borderWidth: '2px' },
      title: { fontSize: '24px' },
    },
  }}
/>
```

### 3. Theme Selection

Choose from built-in themes:

```tsx
// Light theme (default)
<SignIn appearance={{ theme: 'light' }} />

// Dark theme
<SignIn appearance={{ theme: 'dark' }} />

// Auto (follows system preference)
<SignIn appearance={{ theme: 'auto' }} />
```

### 4. CSS Classes

Apply custom class names:

```tsx
<SignIn className="my-custom-signin" />
```

## Theming Guides

- [Customization](./customization.md) - Complete customization guide
- [CSS Variables](./css-variables.md) - Reference for all CSS variables
- [Themes](./themes.md) - Pre-built theme examples

## Common Patterns

### Brand Colors

```tsx
const brandTheme = {
  variables: {
    colorPrimary: '#your-brand-color',
    colorPrimaryHover: '#your-brand-color-dark',
  },
};
```

### Dark Mode

```tsx
const darkTheme = {
  theme: 'dark',
  variables: {
    colorPrimary: '#818cf8',
    colorBackground: '#111827',
  },
};
```

### Global Theme

Apply consistent theming across all components:

```tsx
const theme = {
  variables: {
    colorPrimary: '#6366f1',
    borderRadius: '8px',
  },
};

<SignIn appearance={theme} />
<SignUp appearance={theme} />
<UserProfile appearance={theme} />
```

## Framework Integration

### Tailwind CSS

```tsx
<SignIn
  className="max-w-md mx-auto"
  appearance={{
    variables: {
      colorPrimary: '#6366f1', // Tailwind indigo-500
    },
  }}
/>
```

### Styled Components

```tsx
const StyledSignIn = styled(SignIn)`
  max-width: 450px;
`;
```

### CSS Modules

```tsx
import styles from './Auth.module.css';

<SignIn className={styles.signin} />;
```

## Best Practices

1. **Use CSS variables** for consistent theming
2. **Create a theme object** for reuse across components
3. **Test in both light and dark modes**
4. **Maintain accessibility** with proper contrast ratios
5. **Use Tailwind classes** for layout, theme for colors

## See Also

- [Components](../components/README.md) - Component documentation
- [Customization](./customization.md) - Detailed customization guide
