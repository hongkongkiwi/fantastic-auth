/**
 * Example: Webhook Handler
 * 
 * File: app/api/webhooks/vault/route.ts
 */

import { handleWebhook, verifyWebhook } from '@fantasticauth/nextjs/api';
import { headers } from 'next/headers';

// Option 1: Using handleWebhook helper
export async function POST(request: Request) {
  return handleWebhook(request, {
    // Handle user creation
    'user.created': async (event) => {
      const { userId, email, name } = event.data;
      
      // Send welcome email
      await sendWelcomeEmail(email, name);
      
      // Create user record in your database
      await db.users.create({
        id: userId,
        email,
        name,
        createdAt: event.timestamp,
      });

      return Response.json({ processed: true });
    },

    // Handle user updates
    'user.updated': async (event) => {
      const { userId, ...updates } = event.data;
      
      await db.users.update(userId, updates);

      return Response.json({ processed: true });
    },

    // Handle user deletion
    'user.deleted': async (event) => {
      const { userId } = event.data;
      
      // Clean up user data
      await db.users.delete(userId);

      return Response.json({ processed: true });
    },

    // Handle session events
    'session.created': async (event) => {
      console.log('New session:', event.data.sessionId);
      return Response.json({ processed: true });
    },

    // Handle organization events
    'organization.created': async (event) => {
      const { orgId, name } = event.data;
      
      await db.organizations.create({
        id: orgId,
        name,
      });

      return Response.json({ processed: true });
    },
  });
}

// Option 2: Manual webhook handling for custom logic
export async function POST_manual(request: Request) {
  const payload = await request.json();
  const signature = headers().get('x-vault-signature');
  
  // Verify webhook signature
  if (!verifyWebhook(payload, signature, process.env.VAULT_WEBHOOK_SECRET)) {
    return Response.json(
      { error: 'Invalid signature' },
      { status: 400 }
    );
  }

  const { event } = payload;

  // Custom processing logic
  switch (event.type) {
    case 'user.created':
      await handleUserCreated(event.data);
      break;
    case 'payment.succeeded':
      await handlePaymentSucceeded(event.data);
      break;
    default:
      console.log('Unhandled event:', event.type);
  }

  // Always return 200 to acknowledge receipt
  return Response.json({ received: true });
}

// Helper functions
async function sendWelcomeEmail(email: string, name: string) {
  // Implementation...
}

async function handleUserCreated(data: Record<string, unknown>) {
  // Implementation...
}

async function handlePaymentSucceeded(data: Record<string, unknown>) {
  // Implementation...
}

// Database mock (replace with your actual database)
const db = {
  users: {
    create: async (data: unknown) => { /* ... */ },
    update: async (id: string, data: unknown) => { /* ... */ },
    delete: async (id: string) => { /* ... */ },
  },
  organizations: {
    create: async (data: unknown) => { /* ... */ },
  },
};
