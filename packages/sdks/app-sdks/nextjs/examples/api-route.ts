/**
 * Example: API Route with Authentication
 * 
 * File: app/api/user/route.ts
 */

import { withAuth } from '@fantasticauth/nextjs/api';

// Simple authenticated GET endpoint
export const GET = withAuth(
  async (request, { auth, user, token }) => {
    return Response.json({
      user,
      userId: auth.userId,
      orgId: auth.orgId,
    });
  }
);

// Update user profile
export const PATCH = withAuth(
  async (request, { auth, user, token }) => {
    const body = await request.json();
    
    // Update user via Vault API
    const response = await fetch(
      `${process.env.VAULT_API_URL}/v1/users/${auth.userId}`,
      {
        method: 'PATCH',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
      }
    );

    if (!response.ok) {
      return Response.json(
        { error: 'Failed to update user' },
        { status: response.status }
      );
    }

    const updatedUser = await response.json();
    return Response.json(updatedUser);
  }
);
