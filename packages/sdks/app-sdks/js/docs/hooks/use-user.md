# useUser Hook

The `useUser` hook provides access to user data and profile management functionality.

## Overview

The `useUser` hook family includes:
- `useUser()` - Get current user data
- `useUpdateUser()` - Update user profile
- `useUserManager()` - Complete user management

## useUser

Get the current user object.

### Basic Usage

```tsx
import { useUser } from '@vault/react';

function Profile() {
  const user = useUser();

  if (!user) {
    return <div>Not signed in</div>;
  }

  return (
    <div>
      <h1>{user.profile?.name || user.email}</h1>
      <p>{user.email}</p>
    </div>
  );
}
```

### Return Value

```tsx
User | null
```

Returns the current `User` object or `null` if not signed in.

### User Object

```tsx
interface User {
  id: string;
  tenantId: string;
  email: string;
  emailVerified: boolean;
  status: 'pending' | 'active' | 'suspended' | 'deactivated';
  profile: UserProfile;
  mfaEnabled: boolean;
  mfaMethods: MfaMethod[];
  lastLoginAt?: string;
  createdAt: string;
  updatedAt: string;
}

interface UserProfile {
  name?: string;
  givenName?: string;
  familyName?: string;
  picture?: string;
  phoneNumber?: string;
  [key: string]: any;
}
```

### Examples

#### Display User Information

```tsx
import { useUser } from '@vault/react';

function UserCard() {
  const user = useUser();

  if (!user) return null;

  return (
    <div className="user-card">
      <img
        src={user.profile?.picture || '/default-avatar.png'}
        alt={user.profile?.name}
      />
      <div>
        <h3>{user.profile?.name || user.email}</h3>
        <p>{user.email}</p>
        {user.emailVerified && <span>✓ Verified</span>}
      </div>
    </div>
  );
}
```

#### Check User Status

```tsx
import { useUser } from '@vault/react';

function StatusBadge() {
  const user = useUser();

  if (!user) return null;

  const statusColors = {
    pending: 'yellow',
    active: 'green',
    suspended: 'red',
    deactivated: 'gray',
  };

  return (
    <span className={`badge ${statusColors[user.status]}`}>
      {user.status}
    </span>
  );
}
```

## useUpdateUser

Update user profile with loading and error states.

### Basic Usage

```tsx
import { useUpdateUser } from '@vault/react';
import { useState } from 'react';

function EditProfile() {
  const { updateUser, reloadUser, isLoading, error } = useUpdateUser();
  const [name, setName] = useState('');

  const handleSave = async () => {
    await updateUser({
      profile: { name },
    });
  };

  return (
    <div>
      <input
        value={name}
        onChange={(e) => setName(e.target.value)}
        disabled={isLoading}
      />
      <button onClick={handleSave} disabled={isLoading}>
        {isLoading ? 'Saving...' : 'Save'}
      </button>
      {error && <p>{error.message}</p>}
    </div>
  );
}
```

### Return Value

```tsx
interface UseUpdateUserReturn {
  updateUser: (updates: Partial<User> | Partial<UserProfile>) => Promise<void>;
  reloadUser: () => Promise<void>;
  isLoading: boolean;
  error: ApiError | null;
}
```

| Property | Type | Description |
|----------|------|-------------|
| `updateUser` | `(updates) => Promise<void>` | Update user profile |
| `reloadUser` | `() => Promise<void>` | Refresh user data from server |
| `isLoading` | `boolean` | Whether an operation is in progress |
| `error` | `ApiError \| null` | Last error, if any |

### Examples

#### Update Profile

```tsx
import { useUpdateUser, useUser } from '@vault/react';
import { useState, useEffect } from 'react';

function ProfileEditor() {
  const user = useUser();
  const { updateUser, isLoading, error } = useUpdateUser();
  const [formData, setFormData] = useState({
    name: '',
    phoneNumber: '',
  });

  useEffect(() => {
    if (user) {
      setFormData({
        name: user.profile?.name || '',
        phoneNumber: user.profile?.phoneNumber || '',
      });
    }
  }, [user]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    await updateUser({
      profile: formData,
    });
  };

  return (
    <form onSubmit={handleSubmit}>
      <input
        value={formData.name}
        onChange={(e) => setFormData({ ...formData, name: e.target.value })}
        placeholder="Full name"
        disabled={isLoading}
      />
      <input
        value={formData.phoneNumber}
        onChange={(e) => setFormData({ ...formData, phoneNumber: e.target.value })}
        placeholder="Phone number"
        disabled={isLoading}
      />
      <button type="submit" disabled={isLoading}>
        {isLoading ? 'Saving...' : 'Save Changes'}
      </button>
      {error && <p className="error">{error.message}</p>}
    </form>
  );
}
```

#### Refresh User Data

```tsx
import { useUpdateUser } from '@vault/react';

function RefreshButton() {
  const { reloadUser, isLoading } = useUpdateUser();

  return (
    <button onClick={reloadUser} disabled={isLoading}>
      {isLoading ? 'Refreshing...' : 'Refresh Data'}
    </button>
  );
}
```

## useUserManager

Complete user management including password changes and account deletion.

### Basic Usage

```tsx
import { useUserManager } from '@vault/react';

function AccountSettings() {
  const {
    user,
    isLoaded,
    isLoading,
    error,
    update,
    reload,
    changePassword,
    deleteUser,
  } = useUserManager();

  // Use methods for account management
}
```

### Return Value

```tsx
interface UseUserManagerReturn {
  // State
  user: User | null;
  isLoaded: boolean;
  isLoading: boolean;
  error: ApiError | null;

  // Actions
  update: (updates: Partial<User>) => Promise<void>;
  reload: () => Promise<void>;
  changePassword: (currentPassword: string, newPassword: string) => Promise<void>;
  deleteUser: () => Promise<void>;
}
```

### Examples

#### Change Password

```tsx
import { useUserManager } from '@vault/react';
import { useState } from 'react';

function ChangePasswordForm() {
  const { changePassword, isLoading, error } = useUserManager();
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [success, setSuccess] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSuccess(false);

    try {
      await changePassword(currentPassword, newPassword);
      setSuccess(true);
      setCurrentPassword('');
      setNewPassword('');
    } catch {
      // Error is available in error state
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <input
        type="password"
        value={currentPassword}
        onChange={(e) => setCurrentPassword(e.target.value)}
        placeholder="Current password"
        disabled={isLoading}
      />
      <input
        type="password"
        value={newPassword}
        onChange={(e) => setNewPassword(e.target.value)}
        placeholder="New password"
        disabled={isLoading}
      />
      <button type="submit" disabled={isLoading}>
        {isLoading ? 'Changing...' : 'Change Password'}
      </button>
      {error && <p>{error.message}</p>}
      {success && <p>Password changed successfully!</p>}
    </form>
  );
}
```

#### Delete Account

```tsx
import { useUserManager } from '@vault/react';
import { useRouter } from 'next/router';

function DeleteAccountButton() {
  const { deleteUser, isLoading } = useUserManager();
  const router = useRouter();

  const handleDelete = async () => {
    if (window.confirm('Are you sure? This cannot be undone.')) {
      await deleteUser();
      router.push('/');
    }
  };

  return (
    <button
      onClick={handleDelete}
      disabled={isLoading}
      className="danger"
    >
      {isLoading ? 'Deleting...' : 'Delete Account'}
    </button>
  );
}
```

#### Complete Profile Management

```tsx
import { useUserManager } from '@vault/react';
import { useState, useEffect } from 'react';

function ProfileManagement() {
  const {
    user,
    isLoaded,
    isLoading,
    error,
    update,
    reload,
  } = useUserManager();

  const [formData, setFormData] = useState({
    name: '',
    phoneNumber: '',
  });

  useEffect(() => {
    if (user) {
      setFormData({
        name: user.profile?.name || '',
        phoneNumber: user.profile?.phoneNumber || '',
      });
    }
  }, [user]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    await update({ profile: formData });
  };

  if (!isLoaded) {
    return <div>Loading...</div>;
  }

  if (!user) {
    return <div>Not signed in</div>;
  }

  return (
    <div>
      <h1>Profile Management</h1>
      
      <form onSubmit={handleSubmit}>
        <label>
          Name
          <input
            value={formData.name}
            onChange={(e) => setFormData({ ...formData, name: e.target.value })}
            disabled={isLoading}
          />
        </label>
        
        <label>
          Phone
          <input
            value={formData.phoneNumber}
            onChange={(e) => setFormData({ ...formData, phoneNumber: e.target.value })}
            disabled={isLoading}
          />
        </label>
        
        <button type="submit" disabled={isLoading}>
          {isLoading ? 'Saving...' : 'Save Changes'}
        </button>
      </form>

      {error && <div className="error">{error.message}</div>}

      <div className="account-info">
        <p>Email: {user.email}</p>
        <p>Status: {user.status}</p>
        <p>Joined: {new Date(user.createdAt).toLocaleDateString()}</p>
      </div>
    </div>
  );
}
```

## Comparison

| Hook | Returns | Best For |
|------|---------|----------|
| `useUser()` | `User \| null` | Simple user data display |
| `useUpdateUser()` | Update functions | Profile updates with loading states |
| `useUserManager()` | Full management | Complete account management |

## Testing

Test user hooks:

```tsx
import { renderHook } from '@testing-library/react';
import { useUser, useUpdateUser, VaultProvider } from '@vault/react';

const wrapper = ({ children }) => (
  <VaultProvider config={{ apiUrl: 'https://test', tenantId: 'test' }}>
    {children}
  </VaultProvider>
);

test('useUser returns null when not signed in', () => {
  const { result } = renderHook(() => useUser(), { wrapper });
  expect(result.current).toBeNull();
});

test('useUpdateUser provides update function', () => {
  const { result } = renderHook(() => useUpdateUser(), { wrapper });
  expect(typeof result.current.updateUser).toBe('function');
  expect(result.current.isLoading).toBe(false);
});
```

## See Also

- [useAuth Hook](./use-auth.md) - Authentication state
- [UserButton Component](../components/user-button.md) - User menu
- [UserProfile Component](../components/user-profile.md) - Profile management
