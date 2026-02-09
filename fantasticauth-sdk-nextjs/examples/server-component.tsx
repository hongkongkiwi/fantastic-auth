/**
 * Example: Server Component with Authentication
 */

import { auth, currentUser } from '@vault/nextjs/server';
import { redirect } from 'next/navigation';

// This is a Server Component (no 'use client' directive)
export default async function DashboardPage() {
  // Get auth state
  const { userId, session, isSignedIn, orgId, orgRole } = await auth();

  // Redirect if not authenticated
  if (!isSignedIn) {
    redirect('/sign-in');
  }

  // Get full user object
  const user = await currentUser();

  return (
    <div>
      <h1>Dashboard</h1>
      <p>Welcome, {user?.name}!</p>
      <p>User ID: {userId}</p>
      <p>Session ID: {session?.id}</p>
      <p>Organization: {orgId || 'Personal'}</p>
      <p>Role: {orgRole || 'N/A'}</p>
    </div>
  );
}
