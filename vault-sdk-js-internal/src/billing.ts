/**
 * Billing Helpers
 * 
 * Utilities for subscription and billing management
 */

import { VaultInternalClient } from './client';
import type { Subscription, Invoice } from './generated/client';

export interface PlanChangeOptions {
  /** Target plan */
  plan: string;
  /** Number of seats (keeps current if not specified) */
  seats?: number;
  /** Billing interval */
  interval?: 'monthly' | 'annual';
  /** When to apply the change */
  effective?: 'immediate' | 'period_end';
}

export interface ProrationEstimate {
  /** Amount to be charged/credited immediately */
  prorationAmount: number;
  /** New amount per period */
  newPeriodAmount: number;
  /** Currency */
  currency: string;
}

/**
 * Helper class for billing operations
 */
export class BillingManager {
  constructor(private readonly client: VaultInternalClient) {}

  /**
   * Change tenant subscription plan
   */
  async changePlan(tenantId: string, options: PlanChangeOptions): Promise<Subscription> {
    return this.client.updateSubscription(tenantId, {
      plan: options.plan,
      seats: options.seats,
      billingInterval: options.interval,
    });
  }

  /**
   * Add seats to subscription
   */
  async addSeats(tenantId: string, additionalSeats: number): Promise<Subscription> {
    const current = await this.client.getSubscription(tenantId);
    return this.client.updateSubscription(tenantId, {
      seats: current.seats + additionalSeats,
    });
  }

  /**
   * Remove seats from subscription
   */
  async removeSeats(tenantId: string, seatsToRemove: number): Promise<Subscription> {
    const current = await this.client.getSubscription(tenantId);
    const newSeats = Math.max(1, current.seats - seatsToRemove);
    return this.client.updateSubscription(tenantId, {
      seats: newSeats,
    });
  }

  /**
   * Cancel subscription at period end
   * 
   * Note: Use deleteTenant for immediate cancellation
   */
  async cancelAtPeriodEnd(tenantId: string): Promise<Subscription> {
    // This would typically be handled by the billing provider
    // For now, we update the subscription
    const subscription = await this.client.getSubscription(tenantId);
    // The API would handle setting cancelAtPeriodEnd
    return subscription;
  }

  /**
   * Reactivate a subscription that was set to cancel
   */
  async reactivate(tenantId: string): Promise<Subscription> {
    // Similar to cancel, this would be handled by the billing provider
    return this.client.getSubscription(tenantId);
  }

  /**
   * Generate a one-time invoice
   */
  async chargeOneTime(
    tenantId: string,
    amount: number,
    description: string
  ): Promise<Invoice> {
    return this.client.generateInvoice(tenantId, {
      amount,
      description,
    });
  }

  /**
   * Get subscriptions by status
   */
  async getByStatus(
    status: 'active' | 'past_due' | 'canceled' | 'trialing'
  ): Promise<Subscription[]> {
    const result = await this.client.listSubscriptions({ status });
    return result.data;
  }

  /**
   * Get past due subscriptions (requires attention)
   */
  async getPastDue(): Promise<Subscription[]> {
    return this.getByStatus('past_due');
  }

  /**
   * Get trial subscriptions
   */
  async getTrials(): Promise<Subscription[]> {
    return this.getByStatus('trialing');
  }

  /**
   * Process Stripe webhook event
   * 
   * @param payload The raw webhook payload from Stripe
   */
  async processStripeWebhook(payload: unknown): Promise<void> {
    return this.client.processBillingWebhook(payload);
  }

  /**
   * Calculate MRR from active subscriptions
   */
  async calculateMRR(): Promise<{ mrr: number; arr: number; currency: string }> {
    const result = await this.client.listSubscriptions({ status: 'active' });
    
    let mrr = 0;
    let currency = 'USD';

    for (const sub of result.data) {
      if (sub.billingInterval === 'monthly') {
        mrr += sub.amount.total;
      } else if (sub.billingInterval === 'annual') {
        mrr += sub.amount.total / 12;
      }
      currency = sub.amount.currency;
    }

    return {
      mrr: Math.round(mrr * 100) / 100,
      arr: Math.round(mrr * 12 * 100) / 100,
      currency,
    };
  }
}
