/**
 * Pricing Table Component
 *
 * Displays available billing plans with features and pricing.
 */

import React, { useState } from 'react';
import { useTheme } from '../theme';
import type { BillingPlan, PricingTableProps, PlanFeature } from '../types/billing';

/**
 * PricingTable component for displaying subscription plans
 *
 * @example
 * ```tsx
 * <PricingTable
 *   currentPlanId="pro"
 *   onSelectPlan={(plan) => handleSubscribe(plan)}
 * />
 * ```
 */
export const PricingTable: React.FC<PricingTableProps> = ({
  plans,
  currentPlanId,
  currentInterval = 'month',
  loading = false,
  onSelectPlan,
  onIntervalChange,
  showFeatures = true,
  className = '',
}) => {
  const { appearance } = useTheme();
  const [selectedInterval, setSelectedInterval] = useState<'month' | 'year'>(currentInterval);

  // Handle interval change
  const handleIntervalChange = (interval: 'month' | 'year') => {
    setSelectedInterval(interval);
    onIntervalChange?.(interval);
  };

  // Format price for display
  const formatPrice = (amount: number, currency: string) => {
    const formatter = new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: currency.toUpperCase(),
      minimumFractionDigits: 0,
      maximumFractionDigits: 2,
    });
    return formatter.format(amount / 100);
  };

  // Get features for display
  const getFeatures = (plan: BillingPlan): PlanFeature[] => {
    return plan.features.map((feature) => ({
      name: feature,
      included: true,
      description: feature,
    }));
  };

  // Check if a plan is the current plan
  const isCurrentPlan = (plan: BillingPlan) => plan.id === currentPlanId;

  // Loading state
  if (loading) {
    return (
      <div className={`vault-pricing-table vault-pricing-loading ${className}`}>
        <div className="vault-pricing-skeleton">
          {[1, 2, 3].map((i) => (
            <div key={i} className="vault-pricing-card-skeleton" />
          ))}
        </div>
      </div>
    );
  }

  // Empty state
  if (!plans || plans.length === 0) {
    return (
      <div className={`vault-pricing-table vault-pricing-empty ${className}`}>
        <p>No plans available</p>
      </div>
    );
  }

  return (
    <div
      className={`vault-pricing-table ${className}`}
      style={{
        '--vault-primary': appearance?.variables?.primary,
        '--vault-background': appearance?.variables?.background,
        '--vault-foreground': appearance?.variables?.foreground,
      } as React.CSSProperties}
    >
      {/* Interval Toggle */}
      {onIntervalChange && (
        <div className="vault-pricing-interval-toggle">
          <button
            className={`vault-interval-btn ${selectedInterval === 'month' ? 'active' : ''}`}
            onClick={() => handleIntervalChange('month')}
            type="button"
          >
            Monthly
          </button>
          <button
            className={`vault-interval-btn ${selectedInterval === 'year' ? 'active' : ''}`}
            onClick={() => handleIntervalChange('year')}
            type="button"
          >
            Yearly
            <span className="vault-save-badge">Save 20%</span>
          </button>
        </div>
      )}

      {/* Plans Grid */}
      <div className="vault-pricing-grid">
        {plans.map((plan) => {
          const features = getFeatures(plan);
          const isCurrent = isCurrentPlan(plan);

          return (
            <div
              key={plan.id}
              className={`vault-pricing-card ${isCurrent ? 'current' : ''}`}
              data-plan-id={plan.id}
            >
              {/* Current Plan Badge */}
              {isCurrent && (
                <div className="vault-current-plan-badge">Current Plan</div>
              )}

              {/* Plan Header */}
              <div className="vault-pricing-header">
                <h3 className="vault-plan-name">{plan.name}</h3>
                {plan.description && (
                  <p className="vault-plan-description">{plan.description}</p>
                )}
              </div>

              {/* Plan Price */}
              <div className="vault-pricing-price">
                <span className="vault-price-amount">
                  {formatPrice(plan.amount, plan.currency)}
                </span>
                <span className="vault-price-interval">/{plan.interval}</span>
              </div>

              {/* Plan Features */}
              {showFeatures && features.length > 0 && (
                <ul className="vault-pricing-features">
                  {features.map((feature, index) => (
                    <li
                      key={index}
                      className={`vault-feature-item ${feature.included ? 'included' : 'excluded'}`}
                      title={feature.description}
                    >
                      <svg
                        className="vault-feature-icon"
                        viewBox="0 0 20 20"
                        fill="currentColor"
                      >
                        {feature.included ? (
                          <path
                            fillRule="evenodd"
                            d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z"
                            clipRule="evenodd"
                          />
                        ) : (
                          <path
                            fillRule="evenodd"
                            d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z"
                            clipRule="evenodd"
                          />
                        )}
                      </svg>
                      <span className="vault-feature-name">{feature.name}</span>
                    </li>
                  ))}
                </ul>
              )}

              {/* CTA Button */}
              {onSelectPlan && (
                <button
                  className={`vault-pricing-cta ${isCurrent ? 'current' : ''}`}
                  onClick={() => onSelectPlan(plan)}
                  disabled={isCurrent}
                  type="button"
                >
                  {isCurrent ? 'Current Plan' : 'Subscribe'}
                </button>
              )}
            </div>
          );
        })}
      </div>

      {/* Styles */}
      <style>{`
        .vault-pricing-table {
          --vault-card-bg: var(--vault-background, #ffffff);
          --vault-card-border: #e5e7eb;
          --vault-primary-color: var(--vault-primary, #3b82f6);
          --vault-text-primary: var(--vault-foreground, #111827);
          --vault-text-secondary: #6b7280;
          --vault-success: #10b981;
          
          width: 100%;
        }

        .vault-pricing-interval-toggle {
          display: flex;
          justify-content: center;
          gap: 0.5rem;
          margin-bottom: 2rem;
        }

        .vault-interval-btn {
          padding: 0.5rem 1rem;
          border: 1px solid var(--vault-card-border);
          background: var(--vault-card-bg);
          color: var(--vault-text-primary);
          border-radius: 0.5rem;
          cursor: pointer;
          font-size: 0.875rem;
          transition: all 0.2s;
        }

        .vault-interval-btn.active {
          background: var(--vault-primary-color);
          color: white;
          border-color: var(--vault-primary-color);
        }

        .vault-save-badge {
          margin-left: 0.5rem;
          padding: 0.125rem 0.5rem;
          background: var(--vault-success);
          color: white;
          border-radius: 9999px;
          font-size: 0.75rem;
          font-weight: 600;
        }

        .vault-pricing-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
          gap: 1.5rem;
        }

        .vault-pricing-card {
          position: relative;
          padding: 1.5rem;
          background: var(--vault-card-bg);
          border: 2px solid var(--vault-card-border);
          border-radius: 1rem;
          transition: all 0.2s;
        }

        .vault-pricing-card:hover {
          border-color: var(--vault-primary-color);
          box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }

        .vault-pricing-card.current {
          border-color: var(--vault-primary-color);
          box-shadow: 0 0 0 2px var(--vault-primary-color);
        }

        .vault-current-plan-badge {
          position: absolute;
          top: -1px;
          left: 50%;
          transform: translateX(-50%);
          padding: 0.25rem 1rem;
          background: var(--vault-primary-color);
          color: white;
          font-size: 0.75rem;
          font-weight: 600;
          border-radius: 0 0 0.5rem 0.5rem;
        }

        .vault-pricing-header {
          text-align: center;
          margin-bottom: 1.5rem;
        }

        .vault-plan-name {
          margin: 0 0 0.5rem;
          font-size: 1.5rem;
          font-weight: 700;
          color: var(--vault-text-primary);
        }

        .vault-plan-description {
          margin: 0;
          font-size: 0.875rem;
          color: var(--vault-text-secondary);
        }

        .vault-pricing-price {
          text-align: center;
          margin-bottom: 1.5rem;
        }

        .vault-price-amount {
          font-size: 2.5rem;
          font-weight: 700;
          color: var(--vault-text-primary);
        }

        .vault-price-interval {
          font-size: 1rem;
          color: var(--vault-text-secondary);
        }

        .vault-pricing-features {
          list-style: none;
          padding: 0;
          margin: 0 0 1.5rem;
        }

        .vault-feature-item {
          display: flex;
          align-items: center;
          gap: 0.75rem;
          padding: 0.5rem 0;
          font-size: 0.875rem;
        }

        .vault-feature-item.included {
          color: var(--vault-text-primary);
        }

        .vault-feature-item.excluded {
          color: var(--vault-text-secondary);
          opacity: 0.5;
        }

        .vault-feature-icon {
          width: 1.25rem;
          height: 1.25rem;
          flex-shrink: 0;
        }

        .vault-feature-item.included .vault-feature-icon {
          color: var(--vault-success);
        }

        .vault-feature-item.excluded .vault-feature-icon {
          color: var(--vault-text-secondary);
        }

        .vault-pricing-cta {
          width: 100%;
          padding: 0.75rem 1rem;
          background: var(--vault-primary-color);
          color: white;
          border: none;
          border-radius: 0.5rem;
          font-size: 1rem;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.2s;
        }

        .vault-pricing-cta:hover:not(:disabled) {
          opacity: 0.9;
          transform: translateY(-1px);
        }

        .vault-pricing-cta:disabled {
          background: var(--vault-card-border);
          color: var(--vault-text-secondary);
          cursor: not-allowed;
        }

        .vault-pricing-cta.current {
          background: var(--vault-card-border);
          color: var(--vault-text-secondary);
        }

        .vault-pricing-skeleton {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
          gap: 1.5rem;
        }

        .vault-pricing-card-skeleton {
          height: 400px;
          background: linear-gradient(90deg, #f3f4f6 25%, #e5e7eb 50%, #f3f4f6 75%);
          background-size: 200% 100%;
          animation: vault-skeleton-loading 1.5s infinite;
          border-radius: 1rem;
        }

        @keyframes vault-skeleton-loading {
          0% {
            background-position: 200% 0;
          }
          100% {
            background-position: -200% 0;
          }
        }

        .vault-pricing-empty {
          text-align: center;
          padding: 3rem;
          color: var(--vault-text-secondary);
        }
      `}</style>
    </div>
  );
};

export default PricingTable;
