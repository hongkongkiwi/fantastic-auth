# B2B Organizations Example

Complete guide for implementing multi-tenant organization support.

## Overview

Organizations allow you to build B2B applications with:
- Multiple organizations per user
- Role-based access control
- Organization switching
- Member management

## Basic Setup

```tsx
import { OrganizationSwitcher, useOrganization } from '@fantasticauth/react';

function App() {
  return (
    <div>
      <header>
        <OrganizationSwitcher />
        <UserButton />
      </header>
      
      <main>
        <OrganizationContent />
      </main>
    </div>
  );
}
```

## Organization Content

```tsx
import { useOrganization, useIsOrgAdmin } from '@fantasticauth/react';

function OrganizationContent() {
  const { organization, members } = useOrganization();
  const isAdmin = useIsOrgAdmin();

  if (!organization) {
    return <PersonalDashboard />;
  }

  return (
    <div>
      <h1>{organization.name}</h1>
      
      {isAdmin && <AdminControls />}
      
      <MemberList members={members} />
    </div>
  );
}
```

## Creating Organizations

```tsx
import { useOrganization } from '@fantasticauth/react';

function CreateOrgButton() {
  const { create } = useOrganization();

  const handleCreate = async () => {
    const org = await create({ 
      name: 'My Organization',
      slug: 'my-org'
    });
    console.log('Created:', org);
  };

  return <button onClick={handleCreate}>Create Organization</button>;
}
```

## Role-Based Access

```tsx
import { useOrganizationRole } from '@fantasticauth/react';

function MemberManager() {
  const canManageMembers = useOrganizationRole('admin');

  if (!canManageMembers) {
    return null;
  }

  return (
    <div>
      <h2>Manage Members</h2>
      <InviteForm />
      <MemberList editable />
    </div>
  );
}
```

## See Also

- [useOrganization Hook](../hooks/use-organization.md)
- [OrganizationSwitcher Component](../components/organization-switcher.md)
