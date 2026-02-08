/**
 * Customer Portal Components
 *
 * Components for managing billing through Stripe Customer Portal.
 */

import React, { useState, useCallback } from 'react';
import { useBilling } from '../hooks/useBilling';
import { useTheme } from '../theme';
import type { CustomerPortalButtonProps } from '../types/billing';

/**
 * CustomerPortalButton opens the Stripe Customer Portal
 *
 * @example
 * ```tsx
 * <CustomerPortalButton returnUrl="https://example.com/settings">
 *   Manage Billing
 * </CustomerPortalButton>
 * ```
 */
export const CustomerPortalButton: React.FC<CustomerPortalButtonProps> = ({
  children,
  returnUrl: propReturnUrl,
  disabled = false,
  onOpen,
  onError,
  className = '',
}) => {
  const { createPortalSession } = useBilling();
  const { appearance } = useTheme();
  const [isLoading, setIsLoading] = useState(false);

  // Default return URL to current page
  const returnUrl = propReturnUrl || (typeof window !== 'undefined' ? window.location.href : '/');

  const handleClick = useCallback(async () => {
    if (disabled || isLoading) return;

    setIsLoading(true);

    try {
      const session = await createPortalSession({ returnUrl });
      
      onOpen?.();

      // Open portal in same window
      if (session.url) {
        window.location.href = session.url;
      }
    } catch (error) {
      console.error('Failed to open customer portal:', error);
      onError?.(error instanceof Error ? error : new Error('Failed to open billing portal'));
    } finally {
      setIsLoading(false);
    }
  }, [createPortalSession, returnUrl, disabled, isLoading, onOpen, onError]);

  return (
    <button
      className={`vault-portal-button ${isLoading ? 'loading' : ''} ${className}`}
      onClick={handleClick}
      disabled={disabled || isLoading}
      type="button"
      style={{
        '--vault-primary': appearance?.variables?.primary,
        '--vault-background': appearance?.variables?.background,
        '--vault-foreground': appearance?.variables?.foreground,
      } as React.CSSProperties}
    >
      {isLoading ? (
        <>
          <span className="vault-portal-spinner" />
          <span>Loading...</span>
        </>
      ) : (
        children
      )}

      <style>{`
        .vault-portal-button {
          --vault-primary-color: var(--vault-primary, #3b82f6);
          --vault-text-primary: var(--vault-foreground, #111827);
          --vault-card-bg: var(--vault-background, #ffffff);
          --vault-card-border: #e5e7eb;
          
          display: inline-flex;
          align-items: center;
          justify-content: center;
          gap: 0.5rem;
          padding: 0.75rem 1.5rem;
          background: var(--vault-card-bg);
          color: var(--vault-text-primary);
          border: 1px solid var(--vault-card-border);
          border-radius: 0.5rem;
          font-size: 1rem;
          font-weight: 500;
          cursor: pointer;
          transition: all 0.2s;
        }

        .vault-portal-button:hover:not(:disabled) {
          border-color: var(--vault-primary-color);
          background: rgba(59, 130, 246, 0.05);
        }

        .vault-portal-button:disabled {
          opacity: 0.6;
          cursor: not-allowed;
        }

        .vault-portal-button.loading {
          cursor: wait;
        }

        .vault-portal-spinner {
          width: 1rem;
          height: 1rem;
          border: 2px solid rgba(0, 0, 0, 0.1);
          border-top-color: var(--vault-primary-color);
          border-radius: 50%;
          animation: vault-portal-spin 0.8s linear infinite;
        }

        @keyframes vault-portal-spin {
          to {
            transform: rotate(360deg);
          }
        }
      `}</style>
    </button>
  );
};

/**
 * ManageSubscriptionButton - Opens portal to the subscription management page
 */
export const ManageSubscriptionButton: React.FC<CustomerPortalButtonProps> = (props) => {
  return <CustomerPortalButton {...props} />;
};

/**
 * UpdatePaymentMethodButton - Opens portal to update payment methods
 */
export const UpdatePaymentMethodButton: React.FC<CustomerPortalButtonProps> = (props) => {
  return <CustomerPortalButton {...props} />;
};

/**
 * ViewInvoicesButton - Opens portal to view invoice history
 */
export const ViewInvoicesButton: React.FC<CustomerPortalButtonProps> = (props) => {
  return <CustomerPortalButton {...props} />;
};

/**
 * BillingSettings component - Combines common billing actions
 */
export interface BillingSettingsProps {
  returnUrl?: string;
  showManageSubscription?: boolean;
  showUpdatePayment?: boolean;
  showViewInvoices?: boolean;
  className?: string;
}

export const BillingSettings: React.FC<BillingSettingsProps> = ({
  returnUrl,
  showManageSubscription = true,
  showUpdatePayment = true,
  showViewInvoices = true,
  className = '',
}) => {
  const { appearance } = useTheme();

  return (
    <div
      className={`vault-billing-settings ${className}`}
      style={{
        '--vault-primary': appearance?.variables?.primary,
        '--vault-background': appearance?.variables?.background,
        '--vault-foreground': appearance?.variables?.foreground,
      } as React.CSSProperties}
    >
      <h3 className="vault-billing-settings-title">Billing Settings</h3>
      
      <div className="vault-billing-settings-list">
        {showManageSubscription && (
          <div className="vault-billing-setting-item">
            <div className="vault-billing-setting-info">
              <h4>Subscription Plan</h4>
              <p>Upgrade, downgrade, or cancel your subscription</p>
            </div>
            <CustomerPortalButton returnUrl={returnUrl}>
              Manage
            </CustomerPortalButton>
          </div>
        )}

        {showUpdatePayment && (
          <div className="vault-billing-setting-item">
            <div className="vault-billing-setting-info">
              <h4>Payment Methods</h4>
              <p>Add or update your payment methods</p>
            </div>
            <UpdatePaymentMethodButton returnUrl={returnUrl}>
              Update
            </UpdatePaymentMethodButton>
          </div>
        )}

        {showViewInvoices && (
          <div className="vault-billing-setting-item">
            <div className="vault-billing-setting-info">
              <h4>Billing History</h4>
              <p>View and download your invoices</p>
            </div>
            <ViewInvoicesButton returnUrl={returnUrl}>
              View
            </ViewInvoicesButton>
          </div>
        )}
      </div>

      <style>{`
        .vault-billing-settings {
          --vault-card-bg: var(--vault-background, #ffffff);
          --vault-card-border: #e5e7eb;
          --vault-text-primary: var(--vault-foreground, #111827);
          --vault-text-secondary: #6b7280;
          
          background: var(--vault-card-bg);
          border: 1px solid var(--vault-card-border);
          border-radius: 0.75rem;
          padding: 1.5rem;
        }

        .vault-billing-settings-title {
          margin: 0 0 1.5rem;
          font-size: 1.25rem;
          font-weight: 600;
          color: var(--vault-text-primary);
        }

        .vault-billing-settings-list {
          display: flex;
          flex-direction: column;
          gap: 1.5rem;
        }

        .vault-billing-setting-item {
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 1rem;
          padding-bottom: 1.5rem;
          border-bottom: 1px solid var(--vault-card-border);
        }

        .vault-billing-setting-item:last-child {
          padding-bottom: 0;
          border-bottom: none;
        }

        .vault-billing-setting-info h4 {
          margin: 0 0 0.25rem;
          font-size: 1rem;
          font-weight: 600;
          color: var(--vault-text-primary);
        }

        .vault-billing-setting-info p {
          margin: 0;
          font-size: 0.875rem;
          color: var(--vault-text-secondary);
        }
      `}</style>
    </div>
  );
};

export default CustomerPortalButton;
