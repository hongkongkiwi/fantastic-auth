# UserButton Component

The `UserButton` component displays the user's avatar with a dropdown menu for account management.

## Overview

The UserButton component provides:
- User avatar display (with fallback initials)
- Clickable dropdown menu
- User information display
- Quick links to profile/settings
- Sign out functionality
- Custom menu items support

## Basic Usage

```tsx
import { UserButton } from '@vault/react';

function Header() {
  return <UserButton />;
}
```

## Props

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `showName` | `boolean` | `true` | Display user's name next to avatar |
| `avatarUrl` | `string` | - | Custom avatar URL (overrides user profile picture) |
| `onSignOut` | `() => void` | - | Callback fired after sign out |
| `menuItems` | `Array<{ label: string; onClick: () => void }>` | `[]` | Custom menu items |
| `showManageAccount` | `boolean` | `true` | Show "Manage account" menu item |
| `appearance` | `Appearance` | - | Custom styling configuration |
| `className` | `string` | - | Additional CSS class names |

## Examples

### Basic Usage

```tsx
<UserButton />
```

### Without Name

```tsx
<UserButton showName={false} />
```

### With Custom Avatar

```tsx
<UserButton avatarUrl="https://example.com/avatar.jpg" />
```

### With Custom Menu Items

```tsx
<UserButton
  menuItems={[
    { label: 'Settings', onClick: () => router.push('/settings') },
    { label: 'Billing', onClick: () => router.push('/billing') },
    { label: 'Help', onClick: () => window.open('/help', '_blank') },
  ]}
/>
```

### With Sign Out Handler

```tsx
<UserButton
  onSignOut={() => {
    console.log('User signed out');
    analytics.track('Sign Out');
    router.push('/');
  }}
/>
```

### Without Manage Account Link

```tsx
<UserButton showManageAccount={false} />
```

### With Custom Styling

```tsx
<UserButton
  showName={true}
  appearance={{
    variables: {
      colorPrimary: '#6366f1',
    },
  }}
  className="header-user-button"
/>
```

### Complete Configuration

```tsx
<UserButton
  showName={true}
  avatarUrl="https://example.com/avatar.jpg"
  showManageAccount={true}
  menuItems={[
    { label: 'Dashboard', onClick: () => router.push('/dashboard') },
    { label: 'Settings', onClick: () => router.push('/settings') },
    { label: 'Billing', onClick: () => router.push('/billing') },
  ]}
  onSignOut={() => {
    router.push('/');
    toast.success('Signed out successfully');
  }}
  appearance={{
    variables: {
      colorPrimary: '#6366f1',
      borderRadius: '8px',
    },
  }}
  className="user-menu"
/>
```

## Dropdown Menu

The dropdown menu includes:

1. **User Info Section**
   - Display name (or email prefix if no name)
   - Email address
   - Verification badge (if unverified)

2. **Action Items**
   - Manage account (if `showManageAccount` is true)
   - Custom menu items
   - Sign out

### Menu Structure

```
┌─────────────────────┐
│  [Avatar] John Doe  │  ← User info
│  john@example.com   │
│  [Unverified]       │  ← Optional badge
├─────────────────────┤
│ Manage account      │  ← Default action
│ Dashboard           │  ← Custom item
│ Settings            │  ← Custom item
│ Billing             │  ← Custom item
├─────────────────────┤
│ Sign out            │  ← Default action
└─────────────────────┘
```

## Avatar Display

The avatar is displayed in this priority order:

1. `avatarUrl` prop (if provided)
2. User's profile picture from `user.profile.picture`
3. Fallback with user's initial

```tsx
// Custom avatar URL
<UserButton avatarUrl="https://cdn.example.com/avatar.jpg" />

// Will use user.profile.picture
<UserButton />

// Both will fall back to initials if no image
```

## Customization

### CSS Classes

```tsx
<UserButton className="custom-user-button" />
```

```css
.custom-user-button {
  /* Style the container */
}

.custom-user-button button {
  /* Style the trigger button */
}
```

### Appearance Variables

```tsx
<UserButton
  appearance={{
    variables: {
      colorPrimary: '#6366f1',
      borderRadius: '12px',
    },
  }}
/>
```

## Event Handling

### Sign Out Event

```tsx
<UserButton
  onSignOut={() => {
    // Perform cleanup
    localStorage.removeItem('app-data');
    
    // Track event
    analytics.track('User Signed Out');
    
    // Redirect
    window.location.href = '/';
  }}
/>
```

### Menu Item Clicks

```tsx
const menuItems = [
  {
    label: 'Profile',
    onClick: () => {
      router.push('/profile');
      // Menu closes automatically
    },
  },
  {
    label: 'Billing',
    onClick: () => {
      router.push('/billing');
    },
  },
  {
    label: 'Support',
    onClick: () => {
      window.open('https://support.example.com', '_blank');
    },
  },
];

<UserButton menuItems={menuItems} />;
```

## Conditional Rendering

Hide the UserButton when not signed in:

```tsx
import { UserButton, SignedIn, SignedOut } from '@vault/react';

function Header() {
  return (
    <header>
      <SignedIn>
        <UserButton />
      </SignedIn>
      <SignedOut>
        <a href="/sign-in">Sign In</a>
      </SignedOut>
    </header>
  );
}
```

Or use the `useAuth` hook:

```tsx
import { UserButton, useAuth } from '@vault/react';

function Header() {
  const { isSignedIn } = useAuth();

  return (
    <header>
      {isSignedIn ? <UserButton /> : <a href="/sign-in">Sign In</a>}
    </header>
  );
}
```

## Integration Examples

### With Navigation

```tsx
function Navbar() {
  return (
    <nav style={{ display: 'flex', justifyContent: 'space-between' }}>
      <div className="logo">MyApp</div>
      <div className="nav-items">
        <SignedIn>
          <UserButton
            menuItems={[
              { label: 'Dashboard', onClick: () => router.push('/dashboard') },
              { label: 'Settings', onClick: () => router.push('/settings') },
            ]}
          />
        </SignedIn>
        <SignedOut>
          <a href="/sign-in">Sign In</a>
        </SignedOut>
      </div>
    </nav>
  );
}
```

### With Organization Switcher

```tsx
import { UserButton, OrganizationSwitcher } from '@vault/react';

function Header() {
  return (
    <header style={{ display: 'flex', gap: '1rem' }}>
      <OrganizationSwitcher />
      <UserButton />
    </header>
  );
}
```

## Server-Side Rendering

The UserButton is a client component and should be marked as such:

```tsx
'use client';

import { UserButton } from '@vault/react';

export default function Header() {
  return <UserButton />;
}
```

Or use dynamic imports in Next.js:

```tsx
import dynamic from 'next/dynamic';

const UserButton = dynamic(
  () => import('@vault/react').then((mod) => mod.UserButton),
  { ssr: false }
);
```

## TypeScript

Full TypeScript support:

```tsx
import { UserButton, UserButtonProps } from '@vault/react';

const props: UserButtonProps = {
  showName: true,
  showManageAccount: true,
  menuItems: [
    { label: 'Settings', onClick: () => {} },
  ],
};

<UserButton {...props} />;
```

## Testing

Test the UserButton component:

```tsx
import { render, screen, fireEvent } from '@testing-library/react';
import { UserButton } from '@vault/react';

const mockUser = {
  id: 'user_123',
  email: 'test@example.com',
  profile: {
    name: 'Test User',
  },
};

// Mock the auth context
jest.mock('@vault/react', () => ({
  ...jest.requireActual('@vault/react'),
  useAuth: () => ({
    isSignedIn: true,
    user: mockUser,
    signOut: jest.fn(),
  }),
}));

test('renders user button with name', () => {
  render(<UserButton showName={true} />);
  
  expect(screen.getByText('Test User')).toBeInTheDocument();
});

test('opens dropdown on click', () => {
  render(<UserButton />);
  
  fireEvent.click(screen.getByRole('button'));
  
  expect(screen.getByText('Sign out')).toBeInTheDocument();
  expect(screen.getByText('Manage account')).toBeInTheDocument();
});
```

## Accessibility

The UserButton component includes:

- `aria-expanded` for dropdown state
- `aria-haspopup` for menu indication
- `aria-label` for button description
- `role="menu"` for dropdown
- `role="menuitem"` for menu items
- Keyboard navigation (Escape to close, Tab to navigate)
- Focus management

```tsx
// ARIA attributes included:
// - aria-expanded={isOpen}
// - aria-haspopup="true"
// - aria-label="User menu"
// - role="menu" on dropdown
// - role="menuitem" on items
```

## See Also

- [UserProfile Component](./user-profile.md) - Full profile management
- [SignedIn Component](./control-components.md) - Conditional rendering
- [OrganizationSwitcher Component](./organization-switcher.md) - Organization selection
