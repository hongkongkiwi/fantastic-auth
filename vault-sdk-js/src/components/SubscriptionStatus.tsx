/**
 * Subscription Status Components
 *
 * Components for displaying and managing subscription status.
 */

import React, { useState, useCallback } from 'react';
import { useSubscription, useUsage } from '../hooks/useBilling';
import { useTheme } from '../theme';
import type { SubscriptionStatusProps, UsageMeterProps, Invoice } from '../types/billing';

/**
 * SubscriptionStatus component
 *
 * Displays current subscription details with actions
 *
 * @example
 * ```tsx
 * <SubscriptionStatus
 *   showDetails={true}
 *   showInvoices={true}
 *   onCancel={() => cancelSubscription()}
 * />
 * ```
 */
export const SubscriptionStatus: React.FC<SubscriptionStatusProps> = ({
  subscription: propSubscription,
  showDetails = true,
  showInvoices = false,
  showUsage = false,
  onCancel,
  onResume,
  onUpdate,
  className = '',
}) => {
  const hookSubscription = useSubscription();
  const { usage, percentage: usagePercentage } = useUsage();
  const { appearance } = useTheme();

  // Use prop subscription if provided, otherwise use hook
  const {
    subscription,
    isLoading,
    isActive,
    isTrialing,
    isCanceled,
    daysUntilRenewal,
    daysLeftInTrial,
    willRenew,
  } = propSubscription
    ? {
        subscription: propSubscription,
        isLoading: false,
        isActive: ['active', 'trialing'].includes(propSubscription.status),
        isTrialing: propSubscription.status === 'trialing',
        isCanceled:
          propSubscription.cancelAtPeriodEnd ||
          ['canceled', 'unpaid'].includes(propSubscription.status),
        daysUntilRenewal: Math.max(
          0,
          Math.ceil(
            (new Date(propSubscription.currentPeriodEnd).getTime() - Date.now()) /
              (1000 * 60 * 60 * 24)
          )
        ),
        daysLeftInTrial: propSubscription.trialEnd
          ? Math.max(
              0,
              Math.ceil(
                (new Date(propSubscription.trialEnd).getTime() - Date.now()) /
                  (1000 * 60 * 60 * 24)
              )
            )
          : null,
        willRenew:
          ['active', 'trialing'].includes(propSubscription.status) &&
          !propSubscription.cancelAtPeriodEnd,
      }
    : hookSubscription;

  const [isActionLoading, setIsActionLoading] = useState(false);

  const handleCancel = useCallback(async () => {
    if (!onCancel) return;
    setIsActionLoading(true);
    try {
      await onCancel();
    } finally {
      setIsActionLoading(false);
    }
  }, [onCancel]);

  const handleResume = useCallback(async () => {
    if (!onResume) return;
    setIsActionLoading(true);
    try {
      await onResume();
    } finally {
      setIsActionLoading(false);
    }
  }, [onResume]);

  // Format date for display
  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
    });
  };

  // Get status badge color
  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active':
        return 'success';
      case 'trialing':
        return 'info';
      case 'past_due':
      case 'unpaid':
        return 'warning';
      case 'canceled':
        return 'error';
      default:
        return 'default';
    }
  };

  // Loading state
  if (isLoading) {
    return (
      <div className={`vault-subscription-status loading ${className}`}>
        <div className="vault-subscription-skeleton" />
      </div>
    );
  }

  // No subscription state
  if (!subscription) {
    return (
      <div
        className={`vault-subscription-status empty ${className}`}
        style={{
          '--vault-primary': appearance?.variables?.colorPrimary,
          '--vault-background': appearance?.variables?.colorBackground,
          '--vault-foreground': appearance?.variables?.colorText,
        } as React.CSSProperties}
      >
        <div className="vault-subscription-empty">
          <svg className="vault-empty-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
          </svg>
          <h3>No Active Subscription</h3>
          <p>You don't have an active subscription. Choose a plan to get started.</p>
        </div>

        <style>{`
          .vault-subscription-empty {
            text-align: center;
            padding: 3rem 2rem;
            background: var(--vault-background, #ffffff);
            border: 2px dashed #e5e7eb;
            border-radius: 1rem;
          }

          .vault-empty-icon {
            width: 4rem;
            height: 4rem;
            margin-bottom: 1rem;
            color: #9ca3af;
          }

          .vault-subscription-empty h3 {
            margin: 0 0 0.5rem;
            font-size: 1.25rem;
            font-weight: 600;
            color: var(--vault-foreground, #111827);
          }

          .vault-subscription-empty p {
            margin: 0;
            font-size: 0.875rem;
            color: #6b7280;
          }
        `}</style>
      </div>
    );
  }

  return (
    <div
      className={`vault-subscription-status ${className}`}
      style={{
        '--vault-primary': appearance?.variables?.colorPrimary,
        '--vault-background': appearance?.variables?.colorBackground,
        '--vault-foreground': appearance?.variables?.colorText,
      } as React.CSSProperties}
    >
      {/* Status Header */}
      <div className="vault-subscription-header">
        <div className="vault-subscription-info">
          <h3 className="vault-plan-name">{subscription.plan?.name || 'Subscription'}</h3>
          <span className={`vault-status-badge ${getStatusColor(subscription.status)}`}>
            {subscription.status.replace('_', ' ')}
          </span>
        </div>
        
        {subscription.plan && (
          <div className="vault-plan-price">
            <span className="vault-price-amount">
              ${(subscription.plan.amount / 100).toFixed(2)}
            </span>
            <span className="vault-price-interval">/{subscription.plan.interval}</span>
          </div>
        )}
      </div>

      {/* Subscription Details */}
      {showDetails && (
        <div className="vault-subscription-details">
          {/* Trial Info */}
          {isTrialing && daysLeftInTrial !== null && (
            <div className="vault-detail-item vault-trial-info">
              <span className="vault-detail-label">Trial ends in</span>
              <span className="vault-detail-value vault-trial-days">
                {daysLeftInTrial} days
              </span>
            </div>
          )}

          {/* Renewal Date */}
          {isActive && !isCanceled && (
            <div className="vault-detail-item">
              <span className="vault-detail-label">
                {willRenew ? 'Next billing date' : 'Access until'}
              </span>
              <span className="vault-detail-value">
                {formatDate(subscription.currentPeriodEnd)}
              </span>
            </div>
          )}

          {/* Canceled Info */}
          {isCanceled && (
            <div className="vault-detail-item vault-canceled-info">
              <span className="vault-detail-label">Subscription ends</span>
              <span className="vault-detail-value">
                {formatDate(subscription.currentPeriodEnd)}
              </span>
            </div>
          )}

          {/* Cancel at period end warning */}
          {subscription.cancelAtPeriodEnd && !isCanceled && (
            <div className="vault-cancel-warning">
              <svg viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
              </svg>
              <span>Your subscription will not renew</span>
            </div>
          )}
        </div>
      )}

      {/* Usage Meter */}
      {showUsage && usage && (
        <div className="vault-usage-section">
          <h4>Usage This Period</h4>
          <UsageMeter usage={usage} showPercentage />
        </div>
      )}

      {/* Actions */}
      <div className="vault-subscription-actions">
        {onCancel && isActive && !subscription.cancelAtPeriodEnd && (
          <button
            className="vault-action-btn cancel"
            onClick={handleCancel}
            disabled={isActionLoading}
            type="button"
          >
            {isActionLoading ? 'Processing...' : 'Cancel Subscription'}
          </button>
        )}

        {onResume && subscription.cancelAtPeriodEnd && (
          <button
            className="vault-action-btn resume"
            onClick={handleResume}
            disabled={isActionLoading}
            type="button"
          >
            {isActionLoading ? 'Processing...' : 'Resume Subscription'}
          </button>
        )}
      </div>

      {/* Styles */}
      <style>{`
        .vault-subscription-status {
          --vault-card-bg: var(--vault-background, #ffffff);
          --vault-card-border: #e5e7eb;
          --vault-text-primary: var(--vault-foreground, #111827);
          --vault-text-secondary: #6b7280;
          --vault-primary-color: var(--vault-primary, #3b82f6);
          --vault-success: #10b981;
          --vault-warning: #f59e0b;
          --vault-error: #ef4444;
          --vault-info: #3b82f6;
          
          background: var(--vault-card-bg);
          border: 1px solid var(--vault-card-border);
          border-radius: 0.75rem;
          padding: 1.5rem;
        }

        .vault-subscription-header {
          display: flex;
          justify-content: space-between;
          align-items: flex-start;
          margin-bottom: 1.5rem;
          padding-bottom: 1.5rem;
          border-bottom: 1px solid var(--vault-card-border);
        }

        .vault-subscription-info {
          display: flex;
          flex-direction: column;
          gap: 0.5rem;
        }

        .vault-plan-name {
          margin: 0;
          font-size: 1.25rem;
          font-weight: 600;
          color: var(--vault-text-primary);
        }

        .vault-status-badge {
          display: inline-flex;
          padding: 0.25rem 0.75rem;
          border-radius: 9999px;
          font-size: 0.75rem;
          font-weight: 600;
          text-transform: uppercase;
        }

        .vault-status-badge.success {
          background: rgba(16, 185, 129, 0.1);
          color: var(--vault-success);
        }

        .vault-status-badge.info {
          background: rgba(59, 130, 246, 0.1);
          color: var(--vault-info);
        }

        .vault-status-badge.warning {
          background: rgba(245, 158, 11, 0.1);
          color: var(--vault-warning);
        }

        .vault-status-badge.error {
          background: rgba(239, 68, 68, 0.1);
          color: var(--vault-error);
        }

        .vault-status-badge.default {
          background: #f3f4f6;
          color: #6b7280;
        }

        .vault-plan-price {
          text-align: right;
        }

        .vault-price-amount {
          font-size: 1.5rem;
          font-weight: 700;
          color: var(--vault-text-primary);
        }

        .vault-price-interval {
          font-size: 0.875rem;
          color: var(--vault-text-secondary);
        }

        .vault-subscription-details {
          display: flex;
          flex-direction: column;
          gap: 0.75rem;
          margin-bottom: 1.5rem;
        }

        .vault-detail-item {
          display: flex;
          justify-content: space-between;
          font-size: 0.875rem;
        }

        .vault-detail-label {
          color: var(--vault-text-secondary);
        }

        .vault-detail-value {
          font-weight: 500;
          color: var(--vault-text-primary);
        }

        .vault-trial-info .vault-detail-value {
          color: var(--vault-info);
        }

        .vault-canceled-info .vault-detail-value {
          color: var(--vault-error);
        }

        .vault-cancel-warning {
          display: flex;
          align-items: center;
          gap: 0.5rem;
          padding: 0.75rem;
          background: rgba(245, 158, 11, 0.1);
          border-radius: 0.5rem;
          font-size: 0.875rem;
          color: var(--vault-warning);
        }

        .vault-cancel-warning svg {
          width: 1.25rem;
          height: 1.25rem;
          flex-shrink: 0;
        }

        .vault-usage-section {
          margin-bottom: 1.5rem;
          padding: 1rem;
          background: #f9fafb;
          border-radius: 0.5rem;
        }

        .vault-usage-section h4 {
          margin: 0 0 0.75rem;
          font-size: 0.875rem;
          font-weight: 600;
          color: var(--vault-text-primary);
        }

        .vault-subscription-actions {
          display: flex;
          gap: 0.75rem;
        }

        .vault-action-btn {
          flex: 1;
          padding: 0.75rem 1rem;
          border: none;
          border-radius: 0.5rem;
          font-size: 0.875rem;
          font-weight: 500;
          cursor: pointer;
          transition: all 0.2s;
        }

        .vault-action-btn:disabled {
          opacity: 0.6;
          cursor: not-allowed;
        }

        .vault-action-btn.cancel {
          background: transparent;
          color: var(--vault-error);
          border: 1px solid var(--vault-error);
        }

        .vault-action-btn.cancel:hover:not(:disabled) {
          background: rgba(239, 68, 68, 0.05);
        }

        .vault-action-btn.resume {
          background: var(--vault-primary-color);
          color: white;
        }

        .vault-action-btn.resume:hover:not(:disabled) {
          opacity: 0.9;
        }

        .vault-subscription-skeleton {
          height: 200px;
          background: linear-gradient(90deg, #f3f4f6 25%, #e5e7eb 50%, #f3f4f6 75%);
          background-size: 200% 100%;
          animation: vault-skeleton-pulse 1.5s infinite;
          border-radius: 0.75rem;
        }

        @keyframes vault-skeleton-pulse {
          0% {
            background-position: 200% 0;
          }
          100% {
            background-position: -200% 0;
          }
        }
      `}</style>
    </div>
  );
};

/**
 * UsageMeter component
 *
 * Displays usage with progress bar
 */
export const UsageMeter: React.FC<UsageMeterProps> = ({
  usage,
  showPercentage = true,
  showRemaining = false,
  className = '',
}) => {
  const { appearance } = useTheme();

  const percentage = usage.quota
    ? Math.min(100, (usage.totalUsage / usage.quota.limit) * 100)
    : 0;

  const isNearLimit = usage.quota
    ? percentage >= (usage.quota.warningThreshold || 0.8) * 100
    : false;

  const isOverLimit = usage.quota ? usage.totalUsage > usage.quota.limit : false;

  const remaining = usage.quota ? Math.max(0, usage.quota.limit - usage.totalUsage) : 0;

  const getBarColor = () => {
    if (isOverLimit) return 'var(--vault-error, #ef4444)';
    if (isNearLimit) return 'var(--vault-warning, #f59e0b)';
    return 'var(--vault-primary, #3b82f6)';
  };

  return (
    <div
      className={`vault-usage-meter ${className} ${isOverLimit ? 'over-limit' : ''} ${isNearLimit ? 'near-limit' : ''}`}
      style={{
        '--vault-primary': appearance?.variables?.colorPrimary,
        '--vault-foreground': appearance?.variables?.colorText,
      } as React.CSSProperties}
    >
      {/* Progress Bar */}
      <div className="vault-usage-bar-container">
        <div
          className="vault-usage-bar"
          style={{
            width: `${percentage}%`,
            backgroundColor: getBarColor(),
          }}
        />
      </div>

      {/* Usage Info */}
      <div className="vault-usage-info">
        {showPercentage && (
          <span className="vault-usage-percentage">{percentage.toFixed(0)}%</span>
        )}
        <span className="vault-usage-values">
          {usage.totalUsage.toLocaleString()}
          {usage.quota && ` / ${usage.quota.limit.toLocaleString()}`} {usage.metric}
        </span>
        {showRemaining && remaining > 0 && (
          <span className="vault-usage-remaining">({remaining.toLocaleString()} remaining)</span>
        )}
      </div>

      {/* Warnings */}
      {isOverLimit && (
        <div className="vault-usage-warning error">
          You've exceeded your limit. Please upgrade your plan.
        </div>
      )}
      {isNearLimit && !isOverLimit && (
        <div className="vault-usage-warning warning">
          You're approaching your usage limit.
        </div>
      )}

      <style>{`
        .vault-usage-meter {
          --vault-text-primary: var(--vault-foreground, #111827);
          --vault-text-secondary: #6b7280;
          --vault-primary-color: var(--vault-primary, #3b82f6);
          --vault-success: #10b981;
          --vault-warning: #f59e0b;
          --vault-error: #ef4444;
          --vault-bar-bg: #e5e7eb;
        }

        .vault-usage-bar-container {
          height: 0.5rem;
          background: var(--vault-bar-bg);
          border-radius: 9999px;
          overflow: hidden;
          margin-bottom: 0.5rem;
        }

        .vault-usage-bar {
          height: 100%;
          border-radius: 9999px;
          transition: width 0.3s ease, background-color 0.3s ease;
        }

        .vault-usage-info {
          display: flex;
          align-items: center;
          gap: 0.75rem;
          font-size: 0.875rem;
        }

        .vault-usage-percentage {
          font-weight: 600;
          color: var(--vault-text-primary);
          min-width: 2.5rem;
        }

        .vault-usage-values {
          color: var(--vault-text-secondary);
        }

        .vault-usage-remaining {
          color: var(--vault-text-secondary);
          font-size: 0.75rem;
        }

        .vault-usage-warning {
          margin-top: 0.5rem;
          padding: 0.5rem;
          border-radius: 0.375rem;
          font-size: 0.75rem;
          font-weight: 500;
        }

        .vault-usage-warning.error {
          background: rgba(239, 68, 68, 0.1);
          color: var(--vault-error);
        }

        .vault-usage-warning.warning {
          background: rgba(245, 158, 11, 0.1);
          color: var(--vault-warning);
        }

        .vault-usage-meter.near-limit .vault-usage-percentage {
          color: var(--vault-warning);
        }

        .vault-usage-meter.over-limit .vault-usage-percentage {
          color: var(--vault-error);
        }
      `}</style>
    </div>
  );
};

/**
 * InvoiceList component
 *
 * Displays list of invoices
 */
export interface InvoiceListProps {
  invoices: Invoice[];
  loading?: boolean;
  emptyMessage?: string;
  className?: string;
}

export const InvoiceList: React.FC<InvoiceListProps> = ({
  invoices,
  loading = false,
  emptyMessage = 'No invoices yet',
  className = '',
}) => {
  const { appearance } = useTheme();

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
  };

  const formatAmount = (amount: number, currency: string) => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: currency.toUpperCase(),
    }).format(amount / 100);
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'paid':
        return 'success';
      case 'open':
        return 'warning';
      case 'draft':
        return 'default';
      case 'uncollectible':
      case 'void':
        return 'error';
      default:
        return 'default';
    }
  };

  if (loading) {
    return (
      <div className={`vault-invoice-list loading ${className}`}>
        {[1, 2, 3].map((i) => (
          <div key={i} className="vault-invoice-skeleton" />
        ))}
      </div>
    );
  }

  if (!invoices || invoices.length === 0) {
    return (
      <div
        className={`vault-invoice-list empty ${className}`}
        style={{
          '--vault-foreground': appearance?.variables?.colorText,
        } as React.CSSProperties}
      >
        <p className="vault-invoice-empty-message">{emptyMessage}</p>
      </div>
    );
  }

  return (
    <div
      className={`vault-invoice-list ${className}`}
      style={{
        '--vault-primary': appearance?.variables?.colorPrimary,
        '--vault-background': appearance?.variables?.colorBackground,
        '--vault-foreground': appearance?.variables?.colorText,
      } as React.CSSProperties}
    >
      <table className="vault-invoice-table">
        <thead>
          <tr>
            <th>Date</th>
            <th>Amount</th>
            <th>Status</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          {invoices.map((invoice) => (
            <tr key={invoice.id}>
              <td>{formatDate(invoice.createdAt)}</td>
              <td>{formatAmount(invoice.total, invoice.currency)}</td>
              <td>
                <span className={`vault-invoice-status ${getStatusColor(invoice.status)}`}>
                  {invoice.status}
                </span>
              </td>
              <td>
                {invoice.invoicePdf && (
                  <a
                    href={invoice.invoicePdf}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="vault-invoice-download"
                  >
                    Download
                  </a>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <style>{`
        .vault-invoice-list {
          --vault-card-bg: var(--vault-background, #ffffff);
          --vault-text-primary: var(--vault-foreground, #111827);
          --vault-text-secondary: #6b7280;
          --vault-card-border: #e5e7eb;
          --vault-success: #10b981;
          --vault-warning: #f59e0b;
          --vault-error: #ef4444;
          --vault-primary-color: var(--vault-primary, #3b82f6);
        }

        .vault-invoice-table {
          width: 100%;
          border-collapse: collapse;
          font-size: 0.875rem;
        }

        .vault-invoice-table th {
          text-align: left;
          padding: 0.75rem;
          font-weight: 600;
          color: var(--vault-text-secondary);
          border-bottom: 1px solid var(--vault-card-border);
        }

        .vault-invoice-table td {
          padding: 0.75rem;
          color: var(--vault-text-primary);
          border-bottom: 1px solid var(--vault-card-border);
        }

        .vault-invoice-status {
          display: inline-flex;
          padding: 0.125rem 0.5rem;
          border-radius: 9999px;
          font-size: 0.75rem;
          font-weight: 500;
          text-transform: uppercase;
        }

        .vault-invoice-status.success {
          background: rgba(16, 185, 129, 0.1);
          color: var(--vault-success);
        }

        .vault-invoice-status.warning {
          background: rgba(245, 158, 11, 0.1);
          color: var(--vault-warning);
        }

        .vault-invoice-status.error {
          background: rgba(239, 68, 68, 0.1);
          color: var(--vault-error);
        }

        .vault-invoice-status.default {
          background: #f3f4f6;
          color: #6b7280;
        }

        .vault-invoice-download {
          color: var(--vault-primary-color);
          text-decoration: none;
          font-weight: 500;
        }

        .vault-invoice-download:hover {
          text-decoration: underline;
        }

        .vault-invoice-skeleton {
          height: 3rem;
          background: linear-gradient(90deg, #f3f4f6 25%, #e5e7eb 50%, #f3f4f6 75%);
          background-size: 200% 100%;
          animation: vault-invoice-skeleton-loading 1.5s infinite;
          border-radius: 0.375rem;
          margin-bottom: 0.5rem;
        }

        @keyframes vault-invoice-skeleton-loading {
          0% {
            background-position: 200% 0;
          }
          100% {
            background-position: -200% 0;
          }
        }

        .vault-invoice-empty-message {
          text-align: center;
          color: var(--vault-text-secondary);
          padding: 2rem;
        }
      `}</style>
    </div>
  );
};

export default SubscriptionStatus;
