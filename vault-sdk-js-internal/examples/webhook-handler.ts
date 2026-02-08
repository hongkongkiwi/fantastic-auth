/**
 * Example: Stripe Webhook Handler
 * 
 * This example shows how to handle Stripe webhooks
 * and update tenant subscriptions accordingly.
 */

import express from 'express';
import { VaultInternalClient, BillingManager } from '../src';

const app = express();
app.use(express.raw({ type: 'application/json' }));

const client = new VaultInternalClient({
  baseUrl: process.env.VAULT_API_URL!,
  apiKey: process.env.VAULT_INTERNAL_API_KEY!
});

const billing = new BillingManager(client);

app.post('/webhooks/stripe', async (req, res) => {
  const sig = req.headers['stripe-signature'];
  
  try {
    // Verify webhook signature
    // const event = stripe.webhooks.constructEvent(req.body, sig, endpointSecret);
    const event = JSON.parse(req.body);

    console.log(`Received Stripe event: ${event.type}`);

    switch (event.type) {
      case 'invoice.payment_succeeded': {
        const invoice = event.data.object;
        const tenantId = invoice.metadata?.tenant_id;
        
        if (tenantId) {
          console.log(`Payment succeeded for tenant ${tenantId}`);
          // Tenant is already activated, just log for analytics
        }
        break;
      }

      case 'invoice.payment_failed': {
        const invoice = event.data.object;
        const tenantId = invoice.metadata?.tenant_id;
        
        if (tenantId) {
          console.log(`Payment failed for tenant ${tenantId}`);
          // Could suspend tenant after multiple failures
          // await client.suspendTenant(tenantId, { reason: 'Payment failed' });
        }
        break;
      }

      case 'customer.subscription.deleted': {
        const subscription = event.data.object;
        const tenantId = subscription.metadata?.tenant_id;
        
        if (tenantId) {
          console.log(`Subscription canceled for tenant ${tenantId}`);
          // Optionally downgrade to free plan
          await billing.changePlan(tenantId, { plan: 'free' });
        }
        break;
      }

      case 'customer.subscription.updated': {
        const subscription = event.data.object;
        const tenantId = subscription.metadata?.tenant_id;
        
        if (tenantId) {
          console.log(`Subscription updated for tenant ${tenantId}`);
          // Update local subscription cache
        }
        break;
      }
    }

    // Forward to Vault for processing
    await billing.processStripeWebhook(event);

    res.sendStatus(200);
  } catch (error) {
    console.error('Webhook error:', error);
    res.sendStatus(400);
  }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Webhook handler running on port ${PORT}`);
});
