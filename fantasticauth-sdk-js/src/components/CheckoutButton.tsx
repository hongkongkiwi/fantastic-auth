/**
 * Checkout Button Component
 *
 * Button that creates a Stripe checkout session and redirects to it.
 */

import React, { useState, useCallback } from 'react';
import { useBilling } from '../hooks/useBilling';
import { useTheme } from '../theme';
import type { CheckoutButtonProps } from '../types/billing';

/**
 * CheckoutButton component for initiating subscription checkout
 *
 * @example
 * ```tsx
 * <CheckoutButton
 *   priceId="price_123"
 *   successUrl="https://example.com/success"
 *   cancelUrl="https://example.com/cancel"
 * >
 *   Subscribe Now
 * </CheckoutButton>
 * ```
 */
export const CheckoutButton: React.FC<CheckoutButtonProps> = ({
  priceId,
  successUrl,
  cancelUrl,
  children,
  disabled = false,
  loading: externalLoading = false,
  onCheckout,
  onError,
  className = '',
}) => {
  const { createCheckout } = useBilling();
  const { appearance } = useTheme();
  const [internalLoading, setInternalLoading] = useState(false);

  const isLoading = externalLoading || internalLoading;
  const isDisabled = disabled || isLoading;

  const handleClick = useCallback(async () => {
    if (isDisabled) return;

    setInternalLoading(true);

    try {
      const session = await createCheckout({
        priceId,
        successUrl,
        cancelUrl,
      });

      onCheckout?.(session);

      // Redirect to checkout
      if (session.url) {
        window.location.href = session.url;
      }
    } catch (error) {
      console.error('Checkout failed:', error);
      onError?.(error instanceof Error ? error : new Error('Checkout failed'));
    } finally {
      setInternalLoading(false);
    }
  }, [createCheckout, priceId, successUrl, cancelUrl, onCheckout, onError, isDisabled]);

  return (
    <button
      className={`vault-checkout-button ${isLoading ? 'loading' : ''} ${className}`}
      onClick={handleClick}
      disabled={isDisabled}
      type="button"
      style={{
        '--vault-primary': appearance?.variables?.colorPrimary,
        '--vault-background': appearance?.variables?.colorBackground,
        '--vault-foreground': appearance?.variables?.colorText,
      } as React.CSSProperties}
    >
      {isLoading ? (
        <>
          <span className="vault-checkout-spinner" />
          <span>Loading...</span>
        </>
      ) : (
        children
      )}

      <style>{`
        .vault-checkout-button {
          --vault-primary-color: var(--vault-primary, #3b82f6);
          --vault-text-primary: var(--vault-foreground, #111827);
          
          display: inline-flex;
          align-items: center;
          justify-content: center;
          gap: 0.5rem;
          padding: 0.75rem 1.5rem;
          background: var(--vault-primary-color);
          color: white;
          border: none;
          border-radius: 0.5rem;
          font-size: 1rem;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.2s;
          min-width: 150px;
        }

        .vault-checkout-button:hover:not(:disabled) {
          opacity: 0.9;
          transform: translateY(-1px);
        }

        .vault-checkout-button:disabled {
          opacity: 0.6;
          cursor: not-allowed;
        }

        .vault-checkout-button.loading {
          cursor: wait;
        }

        .vault-checkout-spinner {
          width: 1rem;
          height: 1rem;
          border: 2px solid rgba(255, 255, 255, 0.3);
          border-top-color: white;
          border-radius: 50%;
          animation: vault-checkout-spin 0.8s linear infinite;
        }

        @keyframes vault-checkout-spin {
          to {
            transform: rotate(360deg);
          }
        }
      `}</style>
    </button>
  );
};

/**
 * Quick checkout button with minimal configuration
 * Uses current URL for success/cancel callbacks
 *
 * @example
 * ```tsx
 * <QuickCheckoutButton priceId="price_123">
 *   Subscribe Now
 * </QuickCheckoutButton>
 * ```
 */
export interface QuickCheckoutButtonProps {
  priceId: string;
  children: React.ReactNode;
  successPath?: string;
  cancelPath?: string;
  disabled?: boolean;
  onCheckout?: (session: { url: string }) => void;
  onError?: (error: Error) => void;
  className?: string;
}

export const QuickCheckoutButton: React.FC<QuickCheckoutButtonProps> = ({
  priceId,
  children,
  successPath = '/billing/success',
  cancelPath = '/billing/cancel',
  ...props
}) => {
  const successUrl = typeof window !== 'undefined' 
    ? `${window.location.origin}${successPath}` 
    : successPath;
  const cancelUrl = typeof window !== 'undefined' 
    ? `${window.location.origin}${cancelPath}` 
    : cancelPath;

  return (
    <CheckoutButton
      priceId={priceId}
      successUrl={successUrl}
      cancelUrl={cancelUrl}
      {...props}
    >
      {children}
    </CheckoutButton>
  );
};

export default CheckoutButton;
