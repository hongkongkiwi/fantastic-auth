/**
 * Example: Client Component with Authentication
 */

'use client';

import { useUser, useAuth, useOrganization } from '@fantasticauth/nextjs/client';

// User profile component
export function UserProfile() {
  const { user, isLoaded, isSignedIn } = useUser();
  const { signOut } = useAuth();

  if (!isLoaded) {
    return <div>Loading...</div>;
  }

  if (!isSignedIn || !user) {
    return (
      <div>
        <p>Not signed in</p>
        <a href="/sign-in">Sign In</a>
      </div>
    );
  }

  return (
    <div className="profile">
      {user.imageUrl && (
        <img 
          src={user.imageUrl} 
          alt={user.name} 
          className="avatar"
        />
      )}
      <h2>{user.name}</h2>
      <p>{user.email}</p>
      <button onClick={() => signOut()}>Sign Out</button>
    </div>
  );
}

// Organization info component
export function OrgInfo() {
  const { orgId, orgRole, isLoaded, isSignedIn } = useOrganization();

  if (!isLoaded || !isSignedIn) {
    return null;
  }

  if (!orgId) {
    return <span>Personal Account</span>;
  }

  return (
    <div className="org-info">
      <span>Organization: {orgId}</span>
      <span className="role">Role: {orgRole}</span>
    </div>
  );
}

// Auth state component
export function AuthStatus() {
  const { isLoaded, isSignedIn, userId } = useAuth();

  if (!isLoaded) {
    return <span>Loading...</span>;
  }

  return (
    <div className="auth-status">
      {isSignedIn ? (
        <span className="signed-in">● Signed in ({userId})</span>
      ) : (
        <span className="signed-out">○ Signed out</span>
      )}
    </div>
  );
}
