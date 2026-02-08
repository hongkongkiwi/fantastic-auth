# CreateOrganization Component

The `CreateOrganization` component provides a form for creating new organizations.

## Overview

This component handles:
- Organization name input
- Organization slug generation
- Validation
- Error handling

## Basic Usage

```tsx
import { CreateOrganization } from '@vault/react';

function NewOrganizationPage() {
  return (
    <CreateOrganization
      onCreate={(org) => {
        console.log('Created:', org);
        window.location.href = `/org/${org.slug}`;
      }}
    />
  );
}
```

## Props

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `onCreate` | `(org: Organization) => void` | - | Callback after creation |
| `onError` | `(error: ApiError) => void` | - | Callback on error |
| `redirectUrl` | `string` | - | Redirect after creation |
| `appearance` | `Appearance` | - | Custom styling |
| `className` | `string` | - | CSS class names |

## Examples

### With Custom Styling

```tsx
<CreateOrganization
  onCreate={(org) => router.push(`/org/${org.id}`)}
  appearance={{
    variables: {
      colorPrimary: '#6366f1',
    },
  }}
/>
```

## See Also

- [useOrganization Hook](../hooks/use-organization.md)
- [OrganizationSwitcher Component](./organization-switcher.md)
