# usePermissions Hook

The `usePermissions` hook provides permission checking functionality.

## Basic Usage

```tsx
import { usePermissions } from '@fantasticauth/react';

function AdminPanel() {
  const { has, hasRole, role } = usePermissions();

  if (!hasRole('admin')) {
    return <p>Admin access required</p>;
  }

  return (
    <div>
      {has('org:delete') && <button>Delete Organization</button>}
      {has('billing:write') && <button>Update Billing</button>}
    </div>
  );
}
```

## Return Value

```tsx
interface UsePermissionsReturn {
  has: (permission: string) => boolean;
  hasRole: (role: string) => boolean;
  permissions: string[];
  role: string | null;
  isLoaded: boolean;
}
```

## See Also

- [useOrganization Hook](./use-organization.md)
- [Protect Component](../components/protect.md)
