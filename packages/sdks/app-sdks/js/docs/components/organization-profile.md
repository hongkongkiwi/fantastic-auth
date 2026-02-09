# OrganizationProfile Component

The `OrganizationProfile` component provides organization management functionality.

## Overview

This component includes:
- Organization settings
- Member management
- Billing information (if applicable)
- Danger zone (delete organization)

## Basic Usage

```tsx
import { OrganizationProfile } from '@fantasticauth/react';

function OrganizationSettingsPage() {
  return (
    <OrganizationProfile
      onUpdate={(org) => {
        console.log('Updated:', org);
      }}
    />
  );
}
```

## Props

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `onUpdate` | `(org: Organization) => void` | - | Callback after update |
| `onError` | `(error: ApiError) => void` | - | Callback on error |
| `appearance` | `Appearance` | - | Custom styling |
| `className` | `string` | - | CSS class names |

## See Also

- [OrganizationSwitcher Component](./organization-switcher.md)
- [useOrganization Hook](../hooks/use-organization.md)
