# OrganizationSwitcher Component

The `OrganizationSwitcher` component provides a dropdown for switching between organizations.

## Basic Usage

```tsx
import { OrganizationSwitcher } from '@vault/react';

function Header() {
  return (
    <header>
      <OrganizationSwitcher />
      <UserButton />
    </header>
  );
}
```

## Props

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `hidePersonal` | `boolean` | `false` | Hide personal account option |
| `onSwitch` | `(org: Organization \| null) => void` | - | Callback when organization changes |
| `appearance` | `Appearance` | - | Custom styling |
| `className` | `string` | - | CSS class names |

## Examples

### Hide Personal Account

```tsx
<OrganizationSwitcher hidePersonal={true} />
```

### With Switch Handler

```tsx
<OrganizationSwitcher
  onSwitch={(org) => {
    analytics.track('Organization Switched', {
      orgId: org?.id,
      orgName: org?.name,
    });
  }}
/>
```

## See Also

- [useOrganization Hook](../hooks/use-organization.md)
