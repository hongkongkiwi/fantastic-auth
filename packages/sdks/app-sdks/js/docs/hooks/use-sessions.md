# useSessions Hook

The `useSessions` hook provides session management functionality.

## Basic Usage

```tsx
import { useSessions } from '@fantasticauth/react';

function SessionList() {
  const {
    sessions,
    isLoading,
    error,
    revokeSession,
    revokeAllOtherSessions,
    refresh,
  } = useSessions();

  if (isLoading) return <div>Loading...</div>;

  return (
    <div>
      <h2>Active Sessions</h2>
      {sessions.map((session) => (
        <div key={session.id}>
          <p>Device: {session.userAgent}</p>
          <p>Last active: {session.lastActiveAt}</p>
          {!session.isCurrent && (
            <button onClick={() => revokeSession(session.id)}>
              Revoke
            </button>
          )}
        </div>
      ))}
      
      <button onClick={revokeAllOtherSessions}>
        Sign Out All Other Devices
      </button>
    </div>
  );
}
```

## Return Value

```tsx
interface UseSessionsReturn {
  sessions: SessionInfo[];
  isLoading: boolean;
  error: ApiError | null;
  revokeSession: (sessionId: string) => Promise<void>;
  revokeAllOtherSessions: () => Promise<void>;
  refresh: () => Promise<void>;
}
```

## See Also

- [useSession Hook](./use-session.md)
- [Session Management](../components/session-management.md)
