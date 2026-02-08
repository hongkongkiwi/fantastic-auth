# useSession Hook

The `useSession` hook family provides access to session data and token management.

## Overview

The `useSession` hooks include:
- `useSession()` - Access session data and methods
- `useToken()` - Get the session token
- `useSessions()` - Manage all user sessions
- `useSessionId()` - Get current session ID

## useSession

Access the current session data, get tokens, and refresh sessions.

### Basic Usage

```tsx
import { useSession } from '@vault/react';

function App() {
  const { session, getToken, isLoaded } = useSession();

  if (!isLoaded) {
    return <div>Loading...</div>;
  }

  return (
    <div>
      <p>Session ID: {session?.id}</p>
      <p>Expires: {session?.expiresAt}</p>
    </div>
  );
}
```

### Return Value

```tsx
interface UseSessionReturn {
  session: Session | null;
  isLoaded: boolean;
  getToken: () => Promise<string | null>;
  refresh: () => Promise<void>;
}
```

| Property | Type | Description |
|----------|------|-------------|
| `session` | `Session \| null` | Current session data |
| `isLoaded` | `boolean` | Whether session has loaded |
| `getToken` | `() => Promise<string \| null>` | Get access token for API calls |
| `refresh` | `() => Promise<void>` | Refresh the session manually |

### Session Object

```tsx
interface Session {
  id: string;
  accessToken: string;
  refreshToken: string;
  expiresAt: string;
  user: User;
}
```

### Examples

#### Get Token for API Calls

```tsx
import { useSession } from '@vault/react';
import { useEffect } from 'react';

function DataFetcher() {
  const { getToken } = useSession();

  useEffect(() => {
    const fetchData = async () => {
      const token = await getToken();
      
      if (token) {
        const response = await fetch('/api/data', {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });
        
        const data = await response.json();
        // Handle data
      }
    };

    fetchData();
  }, [getToken]);

  return <div>Loading...</div>;
}
```

#### Manual Session Refresh

```tsx
import { useSession } from '@vault/react';

function RefreshButton() {
  const { refresh, isLoaded } = useSession();

  const handleRefresh = async () => {
    await refresh();
    console.log('Session refreshed');
  };

  return (
    <button onClick={handleRefresh} disabled={!isLoaded}>
      Refresh Session
    </button>
  );
}
```

#### Check Session Expiry

```tsx
import { useSession } from '@vault/react';

function SessionInfo() {
  const { session } = useSession();

  if (!session) {
    return <div>No active session</div>;
  }

  const expiresAt = new Date(session.expiresAt);
  const now = new Date();
  const hoursUntilExpiry = (expiresAt.getTime() - now.getTime()) / (1000 * 60 * 60);

  return (
    <div>
      <p>Session expires: {expiresAt.toLocaleString()}</p>
      {hoursUntilExpiry < 1 && (
        <p className="warning">Session expires soon!</p>
      )}
    </div>
  );
}
```

## useToken

Simple hook to get just the token getter function.

### Basic Usage

```tsx
import { useToken } from '@vault/react';

function ApiClient() {
  const getToken = useToken();

  const makeRequest = async () => {
    const token = await getToken();
    
    return fetch('/api/protected', {
      headers: { Authorization: `Bearer ${token}` },
    });
  };

  // ...
}
```

### Return Value

```tsx
() => Promise<string | null>
```

## useSessions

Manage all user sessions across devices.

### Basic Usage

```tsx
import { useSessions } from '@vault/react';

function SessionManager() {
  const {
    sessions,
    isLoading,
    error,
    listSessions,
    revokeSession,
    revokeAllSessions,
  } = useSessions();

  return (
    <div>
      <h2>Active Sessions</h2>
      {sessions.map((session) => (
        <div key={session.id}>
          <p>{session.userAgent}</p>
          <p>{session.ipAddress}</p>
          <button onClick={() => revokeSession(session.id)}>
            Revoke
          </button>
        </div>
      ))}
      <button onClick={revokeAllSessions}>
        Revoke All Other Sessions
      </button>
    </div>
  );
}
```

### Return Value

```tsx
interface UseSessionsReturn {
  sessions: SessionInfo[];
  isLoading: boolean;
  error: ApiError | null;
  listSessions: () => Promise<void>;
  revokeSession: (sessionId: string) => Promise<void>;
  revokeAllSessions: () => Promise<void>;
}
```

| Property | Type | Description |
|----------|------|-------------|
| `sessions` | `SessionInfo[]` | List of active sessions |
| `isLoading` | `boolean` | Loading state |
| `error` | `ApiError \| null` | Error state |
| `listSessions` | `() => Promise<void>` | Refresh session list |
| `revokeSession` | `(id) => Promise<void>` | Revoke a specific session |
| `revokeAllSessions` | `() => Promise<void>` | Revoke all other sessions |

### SessionInfo

```tsx
interface SessionInfo {
  id: string;
  userId: string;
  userAgent?: string;
  ipAddress?: string;
  createdAt: string;
  lastActiveAt: string;
  expiresAt: string;
  isCurrent: boolean;
}
```

### Examples

#### Session List

```tsx
import { useSessions } from '@vault/react';
import { useEffect } from 'react';

function SessionList() {
  const { sessions, isLoading, listSessions, revokeSession } = useSessions();

  useEffect(() => {
    listSessions();
  }, []);

  if (isLoading) {
    return <div>Loading sessions...</div>;
  }

  return (
    <div className="session-list">
      <h3>Active Sessions</h3>
      {sessions.map((session) => (
        <div key={session.id} className={session.isCurrent ? 'current' : ''}>
          <div className="session-info">
            <p>Device: {parseUserAgent(session.userAgent)}</p>
            <p>IP: {session.ipAddress}</p>
            <p>Last active: {new Date(session.lastActiveAt).toLocaleString()}</p>
            {session.isCurrent && <span className="badge">Current</span>}
          </div>
          {!session.isCurrent && (
            <button onClick={() => revokeSession(session.id)}>
              Sign Out
            </button>
          )}
        </div>
      ))}
    </div>
  );
}

function parseUserAgent(ua?: string): string {
  if (!ua) return 'Unknown device';
  if (ua.includes('Mobile')) return 'Mobile device';
  if (ua.includes('Chrome')) return 'Chrome browser';
  if (ua.includes('Firefox')) return 'Firefox browser';
  if (ua.includes('Safari')) return 'Safari browser';
  return 'Unknown device';
}
```

#### Security Settings

```tsx
import { useSessions } from '@vault/react';

function SecuritySettings() {
  const { revokeAllSessions, isLoading } = useSessions();

  const handleSignOutAll = async () => {
    if (window.confirm('Sign out of all other devices?')) {
      await revokeAllSessions();
      alert('All other sessions have been signed out');
    }
  };

  return (
    <div className="security-settings">
      <h2>Security</h2>
      
      <div className="setting">
        <h3>Active Sessions</h3>
        <p>You're signed in on multiple devices</p>
        <button onClick={handleSignOutAll} disabled={isLoading}>
          {isLoading ? 'Signing out...' : 'Sign Out All Devices'}
        </button>
      </div>
    </div>
  );
}
```

## useSessionId

Get just the current session ID.

### Basic Usage

```tsx
import { useSessionId } from '@vault/react';

function SessionTracker() {
  const sessionId = useSessionId();

  return (
    <div>
      <p>Session ID: {sessionId || 'None'}</p>
    </div>
  );
}
```

### Return Value

```tsx
string | null
```

## API Client Integration

Use session token with your API client:

### Axios

```tsx
import { useToken } from '@vault/react';
import axios from 'axios';

function useApiClient() {
  const getToken = useToken();

  const client = axios.create({
    baseURL: '/api',
  });

  client.interceptors.request.use(async (config) => {
    const token = await getToken();
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  });

  return client;
}
```

### Fetch Wrapper

```tsx
import { useToken } from '@vault/react';

function useFetch() {
  const getToken = useToken();

  return async (url: string, options: RequestInit = {}) => {
    const token = await getToken();
    
    return fetch(url, {
      ...options,
      headers: {
        ...options.headers,
        Authorization: token ? `Bearer ${token}` : '',
      },
    });
  };
}
```

### React Query

```tsx
import { useToken } from '@vault/react';
import { useQuery } from '@tanstack/react-query';

function useUserData() {
  const getToken = useToken();

  return useQuery({
    queryKey: ['user-data'],
    queryFn: async () => {
      const token = await getToken();
      
      const response = await fetch('/api/user-data', {
        headers: { Authorization: `Bearer ${token}` },
      });
      
      if (!response.ok) {
        throw new Error('Failed to fetch');
      }
      
      return response.json();
    },
  });
}
```

## Testing

Test session hooks:

```tsx
import { renderHook } from '@testing-library/react';
import { useSession, useToken, VaultProvider } from '@vault/react';

const wrapper = ({ children }) => (
  <VaultProvider config={{ apiUrl: 'https://test', tenantId: 'test' }}>
    {children}
  </VaultProvider>
);

test('useSession returns initial state', () => {
  const { result } = renderHook(() => useSession(), { wrapper });
  
  expect(result.current.isLoaded).toBe(false);
  expect(result.current.session).toBeNull();
});

test('useToken returns a function', () => {
  const { result } = renderHook(() => useToken(), { wrapper });
  
  expect(typeof result.current).toBe('function');
});
```

## Best Practices

1. **Use `getToken()` for API calls** - Don't access `session.accessToken` directly
2. **Handle null tokens** - Token may be null if not signed in
3. **Don't store tokens** - Let the SDK manage token storage
4. **Use `useToken()` when you only need the token** - More lightweight than `useSession()`

## See Also

- [useAuth Hook](./use-auth.md) - Authentication state
- [useUser Hook](./use-user.md) - User data
- [Session Management](../components/session-management.md) - Pre-built session UI
