/**
 * Vault SDK Billing Types
 *
 * TypeScript types for billing and subscription management.
 */

// ============================================================================
// Plan Types
// ============================================================================

export interface BillingPlan {
  id: string;
  name: string;
  description: string;
  stripePriceId: string;
  amount: number;
  currency: string;
  interval: 'month' | 'year' | 'week' | 'day';
  features: string[];
  metadata: Record<string, any>;
}

export type PlanTier = 'free' | 'starter' | 'pro' | 'enterprise';

export interface PlanFeature {
  name: string;
  included: boolean;
  description?: string;
  limit?: number | string;
}

// ============================================================================
// Subscription Types
// ============================================================================

export type SubscriptionStatus =
  | 'incomplete'
  | 'incomplete_expired'
  | 'trialing'
  | 'active'
  | 'past_due'
  | 'canceled'
  | 'unpaid'
  | 'paused';

export interface Subscription {
  id: string;
  tenantId: string;
  stripeSubscriptionId: string;
  stripeCustomerId: string;
  status: SubscriptionStatus;
  currentPeriodStart: string;
  currentPeriodEnd: string;
  planId: string;
  plan?: BillingPlan;
  quantity: number;
  cancelAtPeriodEnd: boolean;
  trialStart?: string;
  trialEnd?: string;
  canceledAt?: string;
  createdAt: string;
  updatedAt: string;
}

// ============================================================================
// Customer Types
// ============================================================================

export interface BillingCustomer {
  id: string;
  tenantId: string;
  stripeCustomerId: string;
  email: string;
  name?: string;
  phone?: string;
  address?: BillingAddress;
  createdAt: string;
  updatedAt: string;
}

export interface BillingAddress {
  line1?: string;
  line2?: string;
  city?: string;
  state?: string;
  postalCode?: string;
  country?: string;
}

// ============================================================================
// Payment Method Types
// ============================================================================

export interface PaymentMethod {
  id: string;
  tenantId: string;
  stripePaymentMethodId: string;
  type: string;
  isDefault: boolean;
  card?: CardInfo;
  billingDetails?: BillingDetails;
  createdAt: string;
}

export interface CardInfo {
  brand: string;
  last4: string;
  expMonth: number;
  expYear: number;
  country?: string;
  funding?: 'credit' | 'debit' | 'prepaid' | 'unknown';
}

export interface BillingDetails {
  name?: string;
  email?: string;
  phone?: string;
  address?: BillingAddress;
}

// ============================================================================
// Invoice Types
// ============================================================================

export type InvoiceStatus = 'draft' | 'open' | 'paid' | 'uncollectible' | 'void';

export interface Invoice {
  id: string;
  tenantId: string;
  stripeInvoiceId: string;
  subscriptionId?: string;
  status: InvoiceStatus;
  total: number;
  subtotal: number;
  tax: number;
  currency: string;
  invoicePdf?: string;
  hostedInvoiceUrl?: string;
  periodStart?: string;
  periodEnd?: string;
  paidAt?: string;
  createdAt: string;
}

export interface InvoiceLineItem {
  id: string;
  description: string;
  amount: number;
  currency: string;
  quantity?: number;
  period?: {
    start: string;
    end: string;
  };
}

// ============================================================================
// Usage Types
// ============================================================================

export type UsageMetric =
  | 'api_calls'
  | 'storage_bytes'
  | 'users'
  | 'teams'
  | 'compute_seconds'
  | 'bandwidth_bytes'
  | 'events_processed'
  | 'emails_sent'
  | 'sms_sent'
  | 'webhooks_delivered'
  | string;

export interface UsageRecord {
  id: string;
  tenantId: string;
  subscriptionItemId: string;
  quantity: number;
  timestamp: string;
  action: 'increment' | 'set';
}

export interface UsageQuota {
  metric: UsageMetric;
  limit: number;
  warningThreshold?: number;
}

export interface UsageSummary {
  metric: UsageMetric;
  periodStart: string;
  periodEnd: string;
  totalUsage: number;
  quota?: UsageQuota;
}

// ============================================================================
// Checkout & Portal Types
// ============================================================================

export interface CheckoutSession {
  id: string;
  url: string;
  customerId?: string;
  subscriptionId?: string;
  priceId: string;
  mode: 'payment' | 'setup' | 'subscription';
}

export interface PortalSession {
  url: string;
}

export interface CreateCheckoutOptions {
  priceId: string;
  successUrl: string;
  cancelUrl: string;
  customerEmail?: string;
  allowPromotionCodes?: boolean;
  trialDays?: number;
}

export interface CreatePortalOptions {
  returnUrl: string;
}

// ============================================================================
// Request/Response Types
// ============================================================================

export interface CreateSubscriptionRequest {
  priceId: string;
  successUrl: string;
  cancelUrl: string;
}

export interface UpdateSubscriptionRequest {
  newPriceId: string;
}

export interface ReportUsageRequest {
  quantity: number;
  action?: 'increment' | 'set';
}

export interface SubscriptionResponse {
  subscription: Subscription;
  checkoutUrl?: string;
}

export interface BillingStatusResponse {
  billingEnabled: boolean;
  subscription?: Subscription;
  invoices: Invoice[];
  paymentMethods: PaymentMethod[];
  usageThisPeriod?: UsageSummary;
}

export interface ListPlansResponse {
  billingEnabled: boolean;
  plans: BillingPlan[];
}

// ============================================================================
// Billing Summary & Limits
// ============================================================================

export interface BillingSummary {
  subscription?: Subscription;
  invoices: Invoice[];
  paymentMethods: PaymentMethod[];
  usageThisPeriod?: UsageSummary;
}

export interface SubscriptionLimits {
  maxUsers?: number;
  maxStorageGb?: number;
  maxApiCallsPerMonth?: number;
  maxProjects?: number;
  features: string[];
}

// ============================================================================
// Component Props
// ============================================================================

export interface PricingTableProps {
  plans?: BillingPlan[];
  currentPlanId?: string;
  currentInterval?: 'month' | 'year';
  loading?: boolean;
  onSelectPlan?: (plan: BillingPlan) => void;
  onIntervalChange?: (interval: 'month' | 'year') => void;
  showFeatures?: boolean;
  className?: string;
}

export interface CheckoutButtonProps {
  priceId: string;
  successUrl: string;
  cancelUrl: string;
  children: React.ReactNode;
  disabled?: boolean;
  loading?: boolean;
  onCheckout?: (session: CheckoutSession) => void;
  onError?: (error: Error) => void;
  className?: string;
}

export interface CustomerPortalButtonProps {
  children: React.ReactNode;
  returnUrl?: string;
  disabled?: boolean;
  onOpen?: () => void;
  onError?: (error: Error) => void;
  className?: string;
}

export interface SubscriptionStatusProps {
  subscription?: Subscription;
  showDetails?: boolean;
  showInvoices?: boolean;
  showUsage?: boolean;
  onCancel?: () => Promise<void>;
  onResume?: () => Promise<void>;
  onUpdate?: (newPlanId: string) => Promise<void>;
  className?: string;
}

export interface UsageMeterProps {
  usage: UsageSummary;
  showPercentage?: boolean;
  showRemaining?: boolean;
  className?: string;
}

// ============================================================================
// Hook Return Types
// ============================================================================

export interface UseBillingReturn {
  // State
  isLoading: boolean;
  error: Error | null;
  
  // Plans
  plans: BillingPlan[];
  billingEnabled: boolean;
  refreshPlans: () => Promise<void>;
  
  // Subscription
  subscription: Subscription | null;
  refreshSubscription: () => Promise<void>;
  
  // Actions
  createCheckout: (options: CreateCheckoutOptions) => Promise<CheckoutSession>;
  createPortalSession: (options: CreatePortalOptions) => Promise<PortalSession>;
  cancelSubscription: () => Promise<Subscription>;
  resumeSubscription: () => Promise<Subscription>;
  updateSubscription: (newPriceId: string) => Promise<Subscription>;
  reportUsage: (quantity: number, action?: 'increment' | 'set') => Promise<void>;
  
  // Invoices
  invoices: Invoice[];
  refreshInvoices: () => Promise<void>;
  
  // Clear error
  clearError: () => void;
}

export interface UseSubscriptionReturn {
  subscription: Subscription | null;
  isLoading: boolean;
  error: Error | null;
  isActive: boolean;
  isTrialing: boolean;
  isCanceled: boolean;
  daysUntilRenewal: number;
  daysLeftInTrial: number | null;
  willRenew: boolean;
  refresh: () => Promise<void>;
  cancel: () => Promise<Subscription>;
  resume: () => Promise<Subscription>;
  update: (newPriceId: string) => Promise<Subscription>;
}

export interface UseUsageReturn {
  usage: UsageSummary | null;
  isLoading: boolean;
  error: Error | null;
  isNearLimit: boolean;
  isOverLimit: boolean;
  percentage: number;
  remaining: number;
  refresh: () => Promise<void>;
  report: (quantity: number, action?: 'increment' | 'set') => Promise<void>;
}
