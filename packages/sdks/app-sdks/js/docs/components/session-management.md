# Session Management

Guide for implementing session management in your application.

## Overview

Vault provides tools for:
- Viewing active sessions
- Revoking sessions
- Managing session lifecycle

## Using the useSessions Hook

```tsx
import { useSessions } from '@vault/react';

function SessionManager() {
  const {
    sessions,
    isLoading,
    revokeSession,
    revokeAllSessions,
  } = useSessions();

  return (
    <div>
      <h2>Active Sessions</h2>
      {sessions.map((session) => (
        <div key={session.id}>
          <p>{session.userAgent}</p>
          <p>{new Date(session.lastActiveAt).toLocaleString()}</p>
          {session.isCurrent ? (
            <span>Current</span>
          ) : (
            <button onClick={() => revokeSession(session.id)}>
              Revoke
            </button>
          )}
        </div>
      ))}
      
      <button onClick={revokeAllSessions}>
        Sign Out All Other Devices
      </button>
    </div>
  );
}
```

## See Also

- [useSessions Hook](../hooks/use-session.md)
