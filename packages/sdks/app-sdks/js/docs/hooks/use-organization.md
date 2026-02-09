# useOrganization Hook

The `useOrganization` hook provides functionality for B2B organization management.

## Overview

The `useOrganization` hooks include:
- `useOrganization()` - Organization operations
- `useActiveOrganization()` - Get active organization
- `useOrganizationRole()` - Check organization role
- `useIsOrgAdmin()` - Check if user is org admin

## useOrganization

Manage organizations and their members.

### Basic Usage

```tsx
import { useOrganization } from '@fantasticauth/react';

function OrganizationSwitcher() {
  const { organizations, organization, setActive, isLoading } = useOrganization();

  return (
    <select
      value={organization?.id || ''}
      onChange={(e) => setActive(e.target.value || null)}
      disabled={isLoading}
    >
      <option value="">Personal</option>
      {organizations.map((org) => (
        <option key={org.id} value={org.id}>
          {org.name}
        </option>
      ))}
    </select>
  );
}
```

### Return Value

```tsx
interface UseOrganizationReturn {
  organization: Organization | null;
  organizations: Organization[];
  organizationList: Organization[];
  isLoaded: boolean;
  isLoading: boolean;
  members: OrganizationMember[];
  setActive: (orgId: string | null) => void;
  setActiveOrganization: (orgId: string | null) => Promise<void>;
  create: (data: { name: string; slug?: string }) => Promise<Organization>;
  createOrganization: (name: string, slug?: string) => Promise<Organization>;
  leave: (orgId: string) => Promise<void>;
  refreshMembers: () => Promise<void>;
}
```

| Property | Type | Description |
|----------|------|-------------|
| `organization` | `Organization \| null` | Currently active organization |
| `organizations` | `Organization[]` | All user's organizations |
| `isLoaded` | `boolean` | Whether data has loaded |
| `isLoading` | `boolean` | Whether an operation is in progress |
| `members` | `OrganizationMember[]` | Members of active organization |
| `setActive` | `(orgId) => void` | Set active organization (sync) |
| `setActiveOrganization` | `(orgId) => Promise<void>` | Set active organization (async) |
| `create` | `(data) => Promise<Organization>` | Create new organization |
| `createOrganization` | `(name, slug) => Promise<Organization>` | Create with simpler API |
| `leave` | `(orgId) => Promise<void>` | Leave an organization |
| `refreshMembers` | `() => Promise<void>` | Refresh member list |

### Types

```tsx
interface Organization {
  id: string;
  tenantId: string;
  name: string;
  slug: string;
  logoUrl?: string;
  description?: string;
  role: 'owner' | 'admin' | 'member' | 'guest';
  createdAt: string;
  updatedAt: string;
}

interface OrganizationMember {
  id: string;
  userId: string;
  email: string;
  name?: string;
  role: 'owner' | 'admin' | 'member' | 'guest';
  status: 'pending' | 'active' | 'suspended';
  joinedAt?: string;
}
```

### Examples

#### Create Organization

```tsx
import { useOrganization } from '@fantasticauth/react';
import { useState } from 'react';

function CreateOrganizationForm() {
  const { create, isLoading } = useOrganization();
  const [name, setName] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      const org = await create({ name });
      console.log('Created organization:', org);
    } catch (error) {
      console.error('Failed to create:', error);
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <input
        value={name}
        onChange={(e) => setName(e.target.value)}
        placeholder="Organization name"
        disabled={isLoading}
      />
      <button type="submit" disabled={isLoading}>
        {isLoading ? 'Creating...' : 'Create Organization'}
      </button>
    </form>
  );
}
```

#### Organization Selector

```tsx
import { useOrganization } from '@fantasticauth/react';

function OrganizationSelector() {
  const { organizations, organization, setActiveOrganization, isLoading } = useOrganization();

  const handleChange = async (e: React.ChangeEvent<HTMLSelectElement>) => {
    const orgId = e.target.value || null;
    await setActiveOrganization(orgId);
  };

  return (
    <div className="org-selector">
      <label>Organization:</label>
      <select
        value={organization?.id || ''}
        onChange={handleChange}
        disabled={isLoading}
      >
        <option value="">Personal Account</option>
        {organizations.map((org) => (
          <option key={org.id} value={org.id}>
            {org.name} ({org.role})
          </option>
        ))}
      </select>
    </div>
  );
}
```

## useActiveOrganization

Get just the active organization.

### Usage

```tsx
import { useActiveOrganization } from '@fantasticauth/react';

function CurrentOrgBadge() {
  const org = useActiveOrganization();

  if (!org) {
    return <span>Personal</span>;
  }

  return (
    <span className="org-badge">
      {org.name}
    </span>
  );
}
```

## useOrganizationRole

Check if user has a specific organization role.

### Usage

```tsx
import { useOrganizationRole } from '@fantasticauth/react';

function AdminOnlyFeature() {
  const isAdmin = useOrganizationRole('admin');

  if (!isAdmin) {
    return null;
  }

  return <button>Delete Organization</button>;
}
```

## useIsOrgAdmin

Check if user is an organization admin or owner.

### Usage

```tsx
import { useIsOrgAdmin } from '@fantasticauth/react';

function SettingsLink() {
  const isAdmin = useIsOrgAdmin();

  return (
    <nav>
      <a href="/dashboard">Dashboard</a>
      {isAdmin && <a href="/settings">Settings</a>}
    </nav>
  );
}
```

## Complete B2B Example

```tsx
import { useOrganization, useIsOrgAdmin } from '@fantasticauth/react';

function OrganizationDashboard() {
  const {
    organization,
    organizations,
    members,
    setActive,
    create,
    leave,
  } = useOrganization();
  const isAdmin = useIsOrgAdmin();

  return (
    <div>
      <h1>{organization?.name || 'Personal Account'}</h1>
      
      <OrganizationSwitcher
        organizations={organizations}
        active={organization}
        onChange={setActive}
      />
      
      {organization && (
        <>
          <h2>Members</h2>
          <MemberList members={members} />
          
          {isAdmin && (
            <>
              <InviteMemberButton />
              <OrganizationSettings />
            </>
          )}
          
          <LeaveOrganizationButton onLeave={() => leave(organization.id)} />
        </>
      )}
      
      <CreateOrganizationButton onCreate={create} />
    </div>
  );
}
```

## See Also

- [OrganizationSwitcher Component](../components/organization-switcher.md) - Pre-built switcher
- [B2B Guide](../examples/organizations.md) - Complete B2B example
