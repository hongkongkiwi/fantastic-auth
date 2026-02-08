# UserProfile Component

The `UserProfile` component provides a complete profile management page with tabs for personal information, security settings, and account management.

## Overview

The UserProfile component includes:
- **Profile Tab**: Edit personal information (name, phone, etc.)
- **Security Tab**: Change password, view account info
- **Danger Zone**: Delete account functionality

## Basic Usage

```tsx
import { UserProfile } from '@vault/react';

function ProfilePage() {
  return <UserProfile />;
}
```

## Props

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `onUpdate` | `(user: User) => void` | - | Callback fired when profile is updated |
| `appearance` | `Appearance` | - | Custom styling configuration |
| `className` | `string` | - | Additional CSS class names |

## Examples

### Basic Usage

```tsx
<UserProfile />
```

### With Update Handler

```tsx
<UserProfile
  onUpdate={(user) => {
    console.log('Profile updated:', user);
    analytics.track('Profile Updated');
    toast.success('Profile saved successfully');
  }}
/>
```

### With Custom Styling

```tsx
<UserProfile
  appearance={{
    variables: {
      colorPrimary: '#6366f1',
      borderRadius: '8px',
    },
  }}
  className="custom-profile"
/>
```

### Complete Configuration

```tsx
<UserProfile
  onUpdate={(user) => {
    console.log('Updated user:', user);
  }}
  appearance={{
    theme: 'light',
    variables: {
      colorPrimary: '#6366f1',
      borderRadius: '8px',
    },
    elements: {
      button: { padding: '10px 20px' },
      input: { borderWidth: '2px' },
    },
  }}
  className="profile-page"
/>
```

## Tabs

### Profile Tab

Manage personal information:

- Email address (read-only)
- Verification status
- Full name
- First/last name
- Phone number

```tsx
<UserProfile />
// User clicks "Profile" tab
// Edits their information
// Clicks "Save Changes"
```

### Security Tab

Change password and view account details:

- Current password
- New password
- Confirm new password
- Account ID
- Created date
- Last login date

```tsx
// User clicks "Security" tab
// Enters current and new password
// Clicks "Change Password"
```

Password requirements:
- Minimum 12 characters
- Must match confirmation

### Danger Zone

Account deletion:

```tsx
// User clicks "Danger Zone" tab
// Reads warning message
// Clicks "Delete Account"
// Confirms in browser dialog
// Account is permanently deleted
```

⚠️ **Warning**: Account deletion cannot be undone.

## Customization

### CSS Classes

```tsx
<UserProfile className="custom-profile" />
```

```css
.custom-profile {
  max-width: 800px;
  margin: 0 auto;
}

.custom-profile [data-tab="danger"] {
  color: #dc2626;
}
```

### Appearance Variables

```tsx
<UserProfile
  appearance={{
    variables: {
      colorPrimary: '#6366f1',
      colorDanger: '#dc2626',
      borderRadius: '8px',
    },
  }}
/>
```

### Element Overrides

```tsx
<UserProfile
  appearance={{
    elements: {
      button: {
        padding: '12px 24px',
      },
      input: {
        borderWidth: '2px',
        borderColor: '#e5e7eb',
      },
      tabButton: {
        fontSize: '14px',
      },
      dangerButton: {
        backgroundColor: '#dc2626',
      },
    },
  }}
/>
```

## Event Handling

### Profile Update

```tsx
<UserProfile
  onUpdate={(user) => {
    // User object contains updated data
    console.log('Updated profile:', user.profile);
    
    // Show success message
    toast.success('Profile updated successfully');
    
    // Track event
    analytics.track('Profile Updated', {
      userId: user.id,
    });
    
    // Refresh related data
    refreshUserData();
  }}
/>
```

### Password Change

The password change is handled internally, but you can detect success:

```tsx
// Monitor for success message
// The component shows "Password changed successfully"
// You can also watch for auth state changes
```

### Account Deletion

Account deletion triggers sign out:

```tsx
import { useAuth } from '@vault/react';
import { useEffect } from 'react';

function App() {
  const { isSignedIn } = useAuth();

  useEffect(() => {
    if (!isSignedIn) {
      // User may have deleted account
      // Redirect to home
      router.push('/');
    }
  }, [isSignedIn]);

  return <UserProfile />;
}
```

## Integration Examples

### Full Profile Page

```tsx
// pages/profile.tsx
import { UserProfile, Protect } from '@vault/react';

export default function ProfilePage() {
  return (
    <Protect>
      <div className="profile-container">
        <h1>Your Profile</h1>
        <UserProfile
          onUpdate={() => {
            toast.success('Profile updated!');
          }}
        />
      </div>
    </Protect>
  );
}
```

### With Navigation

```tsx
import { UserProfile, UserButton } from '@vault/react';

function ProfileLayout() {
  return (
    <div>
      <header>
        <h1>Account Settings</h1>
        <UserButton />
      </header>
      <main>
        <UserProfile />
      </main>
    </div>
  );
}
```

### Modal/Dialog Usage

```tsx
import { UserProfile } from '@vault/react';
import { Dialog } from '@headlessui/react';

function ProfileModal({ isOpen, onClose }) {
  return (
    <Dialog open={isOpen} onClose={onClose}>
      <Dialog.Panel>
        <UserProfile
          onUpdate={() => {
            onClose();
          }}
        />
      </Dialog.Panel>
    </Dialog>
  );
}
```

## Form Validation

The component validates user input:

### Profile Fields

- **Name**: Optional, any valid string
- **Phone**: Optional, validated format
- **Email**: Read-only, managed separately

### Password Fields

- **Current Password**: Required for change
- **New Password**: Minimum 12 characters
- **Confirm Password**: Must match new password

Error messages are displayed inline:

```
┌─────────────────────────────┐
│  New Password               │
│  [****************]         │
│  Passwords do not match     │ ← Error message
└─────────────────────────────┘
```

## Loading States

The component handles loading states automatically:

- Shows spinner while saving
- Disables buttons during operations
- Prevents concurrent submissions

```tsx
// Button states
"Save Changes" → "Saving..." → "Save Changes"

"Change Password" → "Changing..." → "Change Password"
```

## Error Handling

Errors are displayed inline:

```tsx
<UserProfile
  onUpdate={(user) => {
    // Success case
  }}
/>
// Errors are shown in the component:
// - "Failed to update profile"
// - "Current password is incorrect"
// - "Failed to delete account"
```

## Server-Side Rendering

The UserProfile is a client component:

```tsx
'use client';

import { UserProfile } from '@vault/react';

export default function ProfilePage() {
  return <UserProfile />;
}
```

## TypeScript

Full TypeScript support:

```tsx
import { UserProfile, UserProfileProps, User } from '@vault/react';

const handleUpdate = (user: User) => {
  console.log('Updated:', user.profile);
};

const props: UserProfileProps = {
  onUpdate: handleUpdate,
};

<UserProfile {...props} />;
```

## Testing

Test the UserProfile component:

```tsx
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { UserProfile } from '@vault/react';

const mockUser = {
  id: 'user_123',
  email: 'test@example.com',
  profile: {
    name: 'Test User',
    givenName: 'Test',
    familyName: 'User',
  },
  emailVerified: true,
};

test('renders profile tabs', () => {
  render(<UserProfile />);
  
  expect(screen.getByText('Profile')).toBeInTheDocument();
  expect(screen.getByText('Security')).toBeInTheDocument();
  expect(screen.getByText('Danger Zone')).toBeInTheDocument();
});

test('switches tabs', () => {
  render(<UserProfile />);
  
  fireEvent.click(screen.getByText('Security'));
  
  expect(screen.getByText('Change Password')).toBeInTheDocument();
});

test('shows user information', () => {
  render(<UserProfile />);
  
  expect(screen.getByDisplayValue('Test User')).toBeInTheDocument();
  expect(screen.getByText('test@example.com')).toBeInTheDocument();
});
```

## Accessibility

The UserProfile component includes:

- Semantic form structure
- ARIA labels on all inputs
- Error announcements via `role="alert"`
- Keyboard navigation between tabs
- Focus management
- High contrast mode support

```tsx
// ARIA attributes included:
// - aria-selected on active tab
// - aria-controls for tab panels
// - aria-invalid on invalid inputs
// - aria-describedby linking errors to inputs
// - role="alert" on error messages
```

## See Also

- [UserButton Component](./user-button.md) - Quick user menu
- [useUser Hook](../hooks/use-user.md) - User data management
- [Protect Component](./protect.md) - Route protection
