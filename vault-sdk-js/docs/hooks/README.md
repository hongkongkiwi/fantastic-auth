# Hooks Overview

The Vault React SDK provides a comprehensive set of hooks for accessing authentication state and performing auth-related actions.

## Hook Categories

### Authentication Hooks

Hooks for sign-in, sign-up, and authentication state.

| Hook | Description |
|------|-------------|
| [`useAuth()`](./use-auth.md) | Primary hook for authentication state and actions |
| [`useAuthState()`](./use-auth.md#useauthstate) | Simple auth state check |
| [`useHasRole()`](./use-auth.md#usehasrole) | Check if user has a specific role |
| [`useRequireAuth()`](./use-auth.md#userequireauth) | Require authentication or throw |
| [`useSignIn()`](./use-sign-in.md) | Sign-in with loading/error states |
| [`useSignUp()`](./use-sign-up.md) | Sign-up with loading/error states |

### User Hooks

Hooks for user data and profile management.

| Hook | Description |
|------|-------------|
| [`useUser()`](./use-user.md) | Get current user data |
| [`useUpdateUser()`](./use-user.md#useupdateuser) | Update user profile |
| [`useUserManager()`](./use-user.md#useusermanager) | Complete user management |

### Session Hooks

Hooks for session and token management.

| Hook | Description |
|------|-------------|
| [`useSession()`](./use-session.md) | Access session data |
| [`useToken()`](./use-session.md#usetoken) | Get session token |
| [`useSessions()`](./use-session.md#usesessions) | Manage all user sessions |
| [`useSessionId()`](./use-session.md#usesessionid) | Get current session ID |

### MFA Hooks

Hooks for multi-factor authentication.

| Hook | Description |
|------|-------------|
| [`useMfa()`](./use-mfa.md) | MFA setup and management |
| [`useMfaChallenge()`](./use-mfa.md#usemfachallenge) | Verify MFA during sign-in |

### WebAuthn Hooks

Hooks for passkey/WebAuthn authentication.

| Hook | Description |
|------|-------------|
| [`useWebAuthn()`](./use-webauthn.md) | WebAuthn operations |
| [`useIsWebAuthnSupported()`](./use-webauthn.md#useiswebauthnsupported) | Check browser support |

### Organization Hooks

Hooks for B2B organization management.

| Hook | Description |
|------|-------------|
| [`useOrganization()`](./use-organization.md) | Organization operations |
| [`useActiveOrganization()`](./use-organization.md#useactiveorganization) | Get active organization |
| [`useOrganizationRole()`](./use-organization.md#useorganizationrole) | Check organization role |
| [`useIsOrgAdmin()`](./use-organization.md#useisorgadmin) | Check if org admin |

## Quick Reference

### Most Common Hooks

```tsx
// Check if user is signed in
const { isSignedIn, isLoaded } = useAuth();

// Get current user
const user = useUser();

// Get session token for API calls
const { getToken } = useSession();

// Sign in with loading state
const { signIn, isLoading, error } = useSignIn();

// Manage organizations
const { organizations, setActive } = useOrganization();
```

### Hook Dependencies

All hooks must be used within a `VaultProvider`:

```tsx
import { VaultProvider, useAuth } from '@vault/react';

// ✅ Correct
function App() {
  return (
    <VaultProvider config={{ apiUrl, tenantId }}>
      <MyComponent />
    </VaultProvider>
  );
}

function MyComponent() {
  const { isSignedIn } = useAuth(); // ✅ Works
  return <div>{isSignedIn ? 'Signed In' : 'Signed Out'}</div>;
}

// ❌ Incorrect
function BadComponent() {
  const { isSignedIn } = useAuth(); // ❌ Error: Must be used within VaultProvider
  return <div />;
}
```

## See Also

- [useAuth Hook](./use-auth.md) - Primary authentication hook
- [useUser Hook](./use-user.md) - User data hook
- [useSession Hook](./use-session.md) - Session management hook
- [Components Overview](../components/README.md) - Pre-built components
