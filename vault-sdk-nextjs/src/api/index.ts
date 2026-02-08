/**
 * @vault/nextjs/api - API route handlers for Vault
 * 
 * @example
 * ```tsx
 * // app/api/user/route.ts
 * import { auth } from '@vault/nextjs/server';
 * 
 * export async function GET() {
 *   const { userId } = await auth();
 *   
 *   if (!userId) {
 *     return Response.json({ error: 'Unauthorized' }, { status: 401 });
 *   }
 *   
 *   return Response.json({ userId });
 * }
 * ```
 * 
 * @example
 * ```tsx
 * // app/api/webhooks/vault/route.ts
 * import { verifyWebhook } from '@vault/nextjs/api';
 * 
 * export async function POST(request: Request) {
 *   const payload = await request.json();
 *   const signature = request.headers.get('x-vault-signature');
 *   
 *   if (!verifyWebhook(payload, signature, process.env.VAULT_WEBHOOK_SECRET)) {
 *     return Response.json({ error: 'Invalid signature' }, { status: 400 });
 *   }
 *   
 *   // Handle webhook
 *   return Response.json({ received: true });
 * }
 * ```
 */

export {
  withAuth,
  createRouteHandler,
  verifyWebhook,
  handleWebhook,
} from './routeHandlers';

export type {
  AuthenticatedHandler,
  RouteHandlerConfig,
  WebhookPayload,
  WebhookEvent,
} from './routeHandlers';
