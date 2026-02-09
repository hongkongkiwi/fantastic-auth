# CSS Variables Reference

Complete reference of all CSS variables available for theming Vault components.

## Color Variables

### Primary Colors

| Variable | Default | Description |
|----------|---------|-------------|
| `--vault-color-primary` | `#0066cc` | Primary brand color |
| `--vault-color-primary-hover` | `#0052a3` | Primary color on hover |
| `--vault-color-primary-light` | `#e6f2ff` | Light variant of primary |
| `--vault-color-primary-dark` | `#004c99` | Dark variant of primary |

### Semantic Colors

| Variable | Default | Description |
|----------|---------|-------------|
| `--vault-color-danger` | `#dc2626` | Error/danger color |
| `--vault-color-danger-hover` | `#b91c1c` | Danger color on hover |
| `--vault-color-danger-light` | `#fee2e2` | Light danger background |
| `--vault-color-success` | `#059669` | Success color |
| `--vault-color-success-hover` | `#047857` | Success color on hover |
| `--vault-color-success-light` | `#d1fae5` | Light success background |
| `--vault-color-warning` | `#d97706` | Warning color |
| `--vault-color-warning-hover` | `#b45309` | Warning color on hover |
| `--vault-color-warning-light` | `#fef3c7` | Light warning background |

### Text Colors

| Variable | Default | Description |
|----------|---------|-------------|
| `--vault-color-text` | `#1f2937` | Primary text color |
| `--vault-color-text-secondary` | `#6b7280` | Secondary/muted text |
| `--vault-color-text-tertiary` | `#9ca3af` | Tertiary text |
| `--vault-color-text-inverse` | `#ffffff` | Text on dark backgrounds |
| `--vault-color-text-link` | `#0066cc` | Link text color |

### Background Colors

| Variable | Default | Description |
|----------|---------|-------------|
| `--vault-color-background` | `#ffffff` | Main background |
| `--vault-color-background-secondary` | `#f9fafb` | Secondary background |
| `--vault-color-background-tertiary` | `#f3f4f6` | Tertiary background |
| `--vault-color-background-input` | `#ffffff` | Input background |
| `--vault-color-background-input-focus` | `#ffffff` | Input focus background |

### Border Colors

| Variable | Default | Description |
|----------|---------|-------------|
| `--vault-color-border` | `#e5e7eb` | Default border color |
| `--vault-color-border-hover` | `#d1d5db` | Border on hover |
| `--vault-color-border-focus` | `#0066cc` | Border on focus |
| `--vault-color-border-error` | `#dc2626` | Border in error state |

## Typography Variables

### Font Properties

| Variable | Default | Description |
|----------|---------|-------------|
| `--vault-font-family` | `-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif` | Font family |
| `--vault-font-family-mono` | `ui-monospace, SFMono-Regular, Menlo, Monaco, monospace` | Monospace font |
| `--vault-font-size` | `16px` | Base font size |
| `--vault-font-size-sm` | `14px` | Small font size |
| `--vault-font-size-lg` | `18px` | Large font size |
| `--vault-font-size-xl` | `20px` | Extra large font size |
| `--vault-font-weight-normal` | `400` | Normal font weight |
| `--vault-font-weight-medium` | `500` | Medium font weight |
| `--vault-font-weight-semibold` | `600` | Semibold font weight |
| `--vault-font-weight-bold` | `700` | Bold font weight |
| `--vault-line-height` | `1.5` | Line height |

### Heading Sizes

| Variable | Default | Description |
|----------|---------|-------------|
| `--vault-heading-font-size-h1` | `32px` | H1 font size |
| `--vault-heading-font-size-h2` | `24px` | H2 font size |
| `--vault-heading-font-size-h3` | `20px` | H3 font size |
| `--vault-heading-font-size-h4` | `18px` | H4 font size |
| `--vault-heading-font-weight` | `600` | Heading font weight |

## Spacing Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `--vault-spacing-unit` | `1rem` | Base spacing unit (16px) |
| `--vault-spacing-xs` | `0.25rem` | Extra small spacing (4px) |
| `--vault-spacing-sm` | `0.5rem` | Small spacing (8px) |
| `--vault-spacing-md` | `1rem` | Medium spacing (16px) |
| `--vault-spacing-lg` | `1.5rem` | Large spacing (24px) |
| `--vault-spacing-xl` | `2rem` | Extra large spacing (32px) |
| `--vault-spacing-2xl` | `3rem` | 2x large spacing (48px) |

## Border & Shadow Variables

### Border Radius

| Variable | Default | Description |
|----------|---------|-------------|
| `--vault-border-radius` | `6px` | Default border radius |
| `--vault-border-radius-sm` | `4px` | Small border radius |
| `--vault-border-radius-md` | `6px` | Medium border radius |
| `--vault-border-radius-lg` | `8px` | Large border radius |
| `--vault-border-radius-xl` | `12px` | Extra large border radius |
| `--vault-border-radius-full` | `9999px` | Full/pill border radius |

### Borders

| Variable | Default | Description |
|----------|---------|-------------|
| `--vault-border-width` | `1px` | Default border width |
| `--vault-border-width-thick` | `2px` | Thick border width |

### Shadows

| Variable | Default | Description |
|----------|---------|-------------|
| `--vault-shadow-sm` | `0 1px 2px 0 rgba(0, 0, 0, 0.05)` | Small shadow |
| `--vault-shadow` | `0 1px 3px 0 rgba(0, 0, 0, 0.1)` | Default shadow |
| `--vault-shadow-md` | `0 4px 6px -1px rgba(0, 0, 0, 0.1)` | Medium shadow |
| `--vault-shadow-lg` | `0 10px 15px -3px rgba(0, 0, 0, 0.1)` | Large shadow |
| `--vault-shadow-xl` | `0 20px 25px -5px rgba(0, 0, 0, 0.1)` | Extra large shadow |
| `--vault-shadow-focus` | `0 0 0 3px rgba(0, 102, 204, 0.2)` | Focus ring shadow |

## Component-Specific Variables

### Button Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `--vault-button-padding` | `12px 16px` | Button padding |
| `--vault-button-padding-sm` | `8px 12px` | Small button padding |
| `--vault-button-padding-lg` | `16px 24px` | Large button padding |
| `--vault-button-font-size` | `16px` | Button font size |
| `--vault-button-font-weight` | `600` | Button font weight |

### Input Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `--vault-input-padding` | `10px 12px` | Input padding |
| `--vault-input-height` | `44px` | Input height |
| `--vault-input-border-width` | `1px` | Input border width |
| `--vault-input-placeholder-color` | `#9ca3af` | Placeholder color |

### Card/Container Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `--vault-container-max-width` | `400px` | Container max width |
| `--vault-container-padding` | `24px` | Container padding |
| `--vault-container-background` | `#ffffff` | Container background |
| `--vault-container-border` | `none` | Container border |

## Usage Examples

### Basic Theming

```tsx
<SignIn
  appearance={{
    variables: {
      colorPrimary: '#6366f1',
      borderRadius: '8px',
      fontSize: '16px',
    },
  }}
/>
```

### Dark Theme

```tsx
<SignIn
  appearance={{
    theme: 'dark',
    variables: {
      colorPrimary: '#818cf8',
      colorBackground: '#111827',
      colorText: '#f9fafb',
      borderRadius: '8px',
    },
  }}
/>
```

### Custom Brand Theme

```tsx
const brandTheme = {
  variables: {
    // Colors
    colorPrimary: '#10b981',
    colorPrimaryHover: '#059669',
    colorDanger: '#ef4444',
    colorSuccess: '#10b981',
    
    // Typography
    fontFamily: 'Inter, system-ui, sans-serif',
    fontSize: '16px',
    
    // Spacing
    borderRadius: '12px',
    spacingUnit: '1rem',
    
    // Component-specific
    buttonPadding: '14px 24px',
    inputPadding: '12px 16px',
  },
};

<SignIn appearance={brandTheme} />
```

## CSS Custom Properties Fallback

You can also set CSS custom properties directly:

```css
/* globals.css */
:root {
  --vault-color-primary: #6366f1;
  --vault-border-radius: 8px;
}

@media (prefers-color-scheme: dark) {
  :root {
    --vault-color-primary: #818cf8;
    --vault-color-background: #111827;
  }
}
```

## Variable Inheritance

Variables are inherited by child components:

```tsx
// Parent sets primary color
<VaultProvider
  appearance={{
    variables: {
      colorPrimary: '#6366f1',
    },
  }}
>
  {/* All components inherit the primary color */}
  <SignIn />
  <SignUp />
  <UserProfile />
</VaultProvider>
```

## See Also

- [Customization](./customization.md) - Theming guide
- [Components](../components/README.md) - Component documentation
