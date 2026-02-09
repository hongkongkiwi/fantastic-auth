/**
 * Vault SDK Billing Hook
 *
 * React hook for billing and subscription management.
 */

import { useState, useCallback, useEffect, useRef } from 'react';
import { useVault } from '../context/VaultContext';
import type {
  BillingPlan,
  Subscription,
  Invoice,
  CheckoutSession,
  PortalSession,
  CreateCheckoutOptions,
  CreatePortalOptions,
  UsageSummary,
  UseBillingReturn,
  ListPlansResponse,
  BillingStatusResponse,
  SubscriptionResponse,
} from '../types/billing';

/**
 * Hook for managing billing and subscriptions
 *
 * @example
 * ```tsx
 * function PricingPage() {
 *   const { plans, createCheckout, isLoading } = useBilling();
 *
 *   const handleSubscribe = async (plan: BillingPlan) => {
 *     const session = await createCheckout({
 *       priceId: plan.stripePriceId,
 *       successUrl: window.location.origin + '/success',
 *       cancelUrl: window.location.origin + '/cancel',
 *     });
 *     window.location.href = session.url;
 *   };
 *
 *   return (
 *     <div>
 *       {plans.map(plan => (
 *         <button key={plan.id} onClick={() => handleSubscribe(plan)}>
 *           Subscribe to {plan.name}
 *         </button>
 *       ))}
 *     </div>
 *   );
 * }
 * ```
 */
export function useBilling(): UseBillingReturn {
  const { api } = useVault();

  // State
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [plans, setPlans] = useState<BillingPlan[]>([]);
  const [billingEnabled, setBillingEnabled] = useState(false);
  const [subscription, setSubscription] = useState<Subscription | null>(null);
  const [invoices, setInvoices] = useState<Invoice[]>([]);

  // Refs to prevent memory leaks
  const isMounted = useRef(true);

  useEffect(() => {
    return () => {
      isMounted.current = false;
    };
  }, []);

  const safeSetState = useCallback(<T,>(setter: (value: T) => void, value: T) => {
    if (isMounted.current) {
      setter(value);
    }
  }, []);

  /**
   * Fetch available billing plans
   */
  const refreshPlans = useCallback(async () => {
    safeSetState(setIsLoading, true);
    safeSetState(setError, null);

    try {
      const response = await api.request<ListPlansResponse>('/api/v1/admin/billing/plans');
      safeSetState(setBillingEnabled, response.billingEnabled);
      safeSetState(setPlans, response.plans);
    } catch (err) {
      safeSetState(setError, err instanceof Error ? err : new Error('Failed to load plans'));
    } finally {
      safeSetState(setIsLoading, false);
    }
  }, [api]);

  /**
   * Fetch current subscription
   */
  const refreshSubscription = useCallback(async () => {
    safeSetState(setIsLoading, true);
    safeSetState(setError, null);

    try {
      const response = await api.request<{ subscription: Subscription | null }>(
        '/api/v1/admin/billing/subscription'
      );
      safeSetState(setSubscription, response.subscription);
    } catch (err) {
      safeSetState(setError, err instanceof Error ? err : new Error('Failed to load subscription'));
    } finally {
      safeSetState(setIsLoading, false);
    }
  }, [api]);

  /**
   * Fetch invoices
   */
  const refreshInvoices = useCallback(async () => {
    safeSetState(setIsLoading, true);
    safeSetState(setError, null);

    try {
      const response = await api.request<{ invoices: Invoice[] }>(
        '/api/v1/admin/billing/invoices'
      );
      safeSetState(setInvoices, response.invoices);
    } catch (err) {
      safeSetState(setError, err instanceof Error ? err : new Error('Failed to load invoices'));
    } finally {
      safeSetState(setIsLoading, false);
    }
  }, [api]);

  /**
   * Create a checkout session for subscription
   */
  const createCheckout = useCallback(
    async (options: CreateCheckoutOptions): Promise<CheckoutSession> => {
      safeSetState(setIsLoading, true);
      safeSetState(setError, null);

      try {
        const response = await api.request<SubscriptionResponse>(
          '/api/v1/admin/billing/subscription',
          {
            method: 'POST',
            body: JSON.stringify({
              price_id: options.priceId,
              success_url: options.successUrl,
              cancel_url: options.cancelUrl,
            }),
          }
        );

        // Update subscription state
        safeSetState(setSubscription, response.subscription);

        // Return checkout session if available
        if (response.checkoutUrl) {
          return {
            id: response.subscription.id,
            url: response.checkoutUrl,
            priceId: options.priceId,
            mode: 'subscription',
          };
        }

        throw new Error('No checkout URL returned');
      } catch (err) {
        const error = err instanceof Error ? err : new Error('Failed to create checkout');
        safeSetState(setError, error);
        throw error;
      } finally {
        safeSetState(setIsLoading, false);
      }
    },
    [api]
  );

  /**
   * Create a customer portal session
   */
  const createPortalSession = useCallback(
    async (options: CreatePortalOptions): Promise<PortalSession> => {
      safeSetState(setIsLoading, true);
      safeSetState(setError, null);

      try {
        const response = await api.request<PortalSession>('/api/v1/admin/billing/portal', {
          method: 'POST',
          body: JSON.stringify({
            return_url: options.returnUrl,
          }),
        });

        return response;
      } catch (err) {
        const error = err instanceof Error ? err : new Error('Failed to create portal session');
        safeSetState(setError, error);
        throw error;
      } finally {
        safeSetState(setIsLoading, false);
      }
    },
    [api]
  );

  /**
   * Cancel subscription at period end
   */
  const cancelSubscription = useCallback(async (): Promise<Subscription> => {
    safeSetState(setIsLoading, true);
    safeSetState(setError, null);

    try {
      const response = await api.request<{ subscription: Subscription }>(
        '/api/v1/admin/billing/subscription/cancel',
        { method: 'POST' }
      );

      safeSetState(setSubscription, response.subscription);
      return response.subscription;
    } catch (err) {
      const error = err instanceof Error ? err : new Error('Failed to cancel subscription');
      safeSetState(setError, error);
      throw error;
    } finally {
      safeSetState(setIsLoading, false);
    }
  }, [api]);

  /**
   * Resume canceled subscription
   */
  const resumeSubscription = useCallback(async (): Promise<Subscription> => {
    safeSetState(setIsLoading, true);
    safeSetState(setError, null);

    try {
      const response = await api.request<{ subscription: Subscription }>(
        '/api/v1/admin/billing/subscription/resume',
        { method: 'POST' }
      );

      safeSetState(setSubscription, response.subscription);
      return response.subscription;
    } catch (err) {
      const error = err instanceof Error ? err : new Error('Failed to resume subscription');
      safeSetState(setError, error);
      throw error;
    } finally {
      safeSetState(setIsLoading, false);
    }
  }, [api]);

  /**
   * Update subscription to new plan
   */
  const updateSubscription = useCallback(
    async (newPriceId: string): Promise<Subscription> => {
      safeSetState(setIsLoading, true);
      safeSetState(setError, null);

      try {
        const response = await api.request<{ subscription: Subscription }>(
          '/api/v1/admin/billing/subscription',
          {
            method: 'PUT',
            body: JSON.stringify({ new_price_id: newPriceId }),
          }
        );

        safeSetState(setSubscription, response.subscription);
        return response.subscription;
      } catch (err) {
        const error = err instanceof Error ? err : new Error('Failed to update subscription');
        safeSetState(setError, error);
        throw error;
      } finally {
        safeSetState(setIsLoading, false);
      }
    },
    [api]
  );

  /**
   * Report usage for metered billing
   */
  const reportUsage = useCallback(
    async (quantity: number, action: 'increment' | 'set' = 'increment'): Promise<void> => {
      try {
        await api.request('/api/v1/admin/billing/usage', {
          method: 'POST',
          body: JSON.stringify({ quantity, action }),
        });
      } catch (err) {
        const error = err instanceof Error ? err : new Error('Failed to report usage');
        safeSetState(setError, error);
        throw error;
      }
    },
    [api]
  );

  /**
   * Clear error state
   */
  const clearError = useCallback(() => {
    safeSetState(setError, null);
  }, []);

  // Load plans on mount
  useEffect(() => {
    refreshPlans();
  }, [refreshPlans]);

  return {
    // State
    isLoading,
    error,

    // Plans
    plans,
    billingEnabled,
    refreshPlans,

    // Subscription
    subscription,
    refreshSubscription,

    // Actions
    createCheckout,
    createPortalSession,
    cancelSubscription,
    resumeSubscription,
    updateSubscription,
    reportUsage,

    // Invoices
    invoices,
    refreshInvoices,

    // Clear error
    clearError,
  };
}

/**
 * Hook for managing a specific subscription
 *
 * @example
 * ```tsx
 * function SubscriptionDetails() {
 *   const { subscription, isActive, daysUntilRenewal, cancel } = useSubscription();
 *
 *   if (!subscription) return <div>No subscription</div>;
 *
 *   return (
 *     <div>
 *       <p>Status: {subscription.status}</p>
 *       <p>Renews in: {daysUntilRenewal} days</p>
 *       <button onClick={cancel}>Cancel</button>
 *     </div>
 *   );
 * }
 * ```
 */
export function useSubscription() {
  const { subscription, refreshSubscription, isLoading, error } = useBilling();

  const isActive = subscription
    ? ['active', 'trialing'].includes(subscription.status)
    : false;

  const isTrialing = subscription?.status === 'trialing';

  const isCanceled = subscription
    ? subscription.cancelAtPeriodEnd || ['canceled', 'unpaid'].includes(subscription.status)
    : false;

  const daysUntilRenewal = subscription
    ? Math.max(
        0,
        Math.ceil(
          (new Date(subscription.currentPeriodEnd).getTime() - Date.now()) /
            (1000 * 60 * 60 * 24)
        )
      )
    : 0;

  const daysLeftInTrial = subscription?.trialEnd
    ? Math.max(
        0,
        Math.ceil(
          (new Date(subscription.trialEnd).getTime() - Date.now()) / (1000 * 60 * 60 * 24)
        )
      )
    : null;

  const willRenew = isActive && !subscription?.cancelAtPeriodEnd;

  return {
    subscription,
    isLoading,
    error,
    isActive,
    isTrialing,
    isCanceled,
    daysUntilRenewal,
    daysLeftInTrial,
    willRenew,
    refresh: refreshSubscription,
    cancel: useBilling().cancelSubscription,
    resume: useBilling().resumeSubscription,
    update: useBilling().updateSubscription,
  };
}

/**
 * Hook for managing usage-based billing
 *
 * @example
 * ```tsx
 * function UsageMeter() {
 *   const { usage, percentage, isNearLimit } = useUsage();
 *
 *   return (
 *     <div>
 *       <progress value={percentage} max={100} />
 *       {isNearLimit && <p>You're approaching your limit!</p>}
 *     </div>
 *   );
 * }
 * ```
 */
export function useUsage() {
  const [usage, setUsage] = useState<UsageSummary | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const { api } = useVault();

  const refresh = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      const response = await api.request<{ usageThisPeriod: UsageSummary | null }>(
        '/api/v1/admin/billing/status'
      );
      setUsage(response.usageThisPeriod);
    } catch (err) {
      setError(err instanceof Error ? err : new Error('Failed to load usage'));
    } finally {
      setIsLoading(false);
    }
  }, [api]);

  const report = useCallback(
    async (quantity: number, action: 'increment' | 'set' = 'increment') => {
      try {
        await api.request('/api/v1/admin/billing/usage', {
          method: 'POST',
          body: JSON.stringify({ quantity, action }),
        });
        // Refresh usage after reporting
        await refresh();
      } catch (err) {
        setError(err instanceof Error ? err : new Error('Failed to report usage'));
        throw err;
      }
    },
    [api, refresh]
  );

  const percentage = usage?.quota
    ? Math.min(100, (usage.totalUsage / usage.quota.limit) * 100)
    : 0;

  const isNearLimit = usage?.quota
    ? percentage >= (usage.quota.warningThreshold || 0.8) * 100 && percentage < 100
    : false;

  const isOverLimit = usage?.quota ? usage.totalUsage > usage.quota.limit : false;

  const remaining = usage?.quota
    ? Math.max(0, usage.quota.limit - usage.totalUsage)
    : 0;

  // Load usage on mount
  useEffect(() => {
    refresh();
  }, [refresh]);

  return {
    usage,
    isLoading,
    error,
    isNearLimit,
    isOverLimit,
    percentage,
    remaining,
    refresh,
    report,
  };
}
