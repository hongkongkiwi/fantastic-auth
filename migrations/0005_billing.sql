-- Billing and subscription tables
-- Stores Stripe billing information and subscription status

-- Subscription plans/products
CREATE TABLE billing_plans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    stripe_product_id VARCHAR(255) UNIQUE NOT NULL,
    stripe_price_id VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    tier VARCHAR(50) NOT NULL, -- free, starter, pro, enterprise
    price_cents INTEGER NOT NULL,
    interval VARCHAR(50) NOT NULL, -- month, year
    features JSONB NOT NULL DEFAULT '[]',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Tenant subscriptions
CREATE TABLE subscriptions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    stripe_customer_id VARCHAR(255),
    stripe_subscription_id VARCHAR(255),
    stripe_price_id VARCHAR(255),
    plan_id UUID REFERENCES billing_plans(id),
    status VARCHAR(50) NOT NULL DEFAULT 'incomplete', -- incomplete, incomplete_expired, trialing, active, past_due, canceled, unpaid, paused
    current_period_start TIMESTAMPTZ,
    current_period_end TIMESTAMPTZ,
    trial_start TIMESTAMPTZ,
    trial_end TIMESTAMPTZ,
    cancel_at TIMESTAMPTZ,
    canceled_at TIMESTAMPTZ,
    ended_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id)
);

-- Payment methods
CREATE TABLE payment_methods (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    stripe_payment_method_id VARCHAR(255) UNIQUE NOT NULL,
    type VARCHAR(50) NOT NULL, -- card, bank_transfer, etc
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    card_brand VARCHAR(50),
    card_last4 VARCHAR(4),
    card_exp_month INTEGER,
    card_exp_year INTEGER,
    billing_email VARCHAR(255),
    billing_name VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Invoices
CREATE TABLE invoices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    stripe_invoice_id VARCHAR(255) UNIQUE NOT NULL,
    stripe_subscription_id VARCHAR(255),
    status VARCHAR(50) NOT NULL, -- draft, open, paid, uncollectible, void
    total_cents INTEGER NOT NULL,
    subtotal_cents INTEGER NOT NULL,
    tax_cents INTEGER NOT NULL DEFAULT 0,
    currency VARCHAR(3) NOT NULL DEFAULT 'usd',
    invoice_pdf_url TEXT,
    hosted_invoice_url TEXT,
    period_start TIMESTAMPTZ,
    period_end TIMESTAMPTZ,
    paid_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Usage records (for metered billing)
CREATE TABLE usage_records (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    stripe_subscription_item_id VARCHAR(255) NOT NULL,
    quantity INTEGER NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    action VARCHAR(50) NOT NULL, -- increment, set
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Billing events log
CREATE TABLE billing_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    event_type VARCHAR(100) NOT NULL,
    stripe_event_id VARCHAR(255),
    data JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_billing_plans_tier ON billing_plans(tier) WHERE is_active = TRUE;
CREATE INDEX idx_subscriptions_tenant ON subscriptions(tenant_id);
CREATE INDEX idx_subscriptions_stripe_customer ON subscriptions(stripe_customer_id);
CREATE INDEX idx_subscriptions_status ON subscriptions(status);
CREATE INDEX idx_payment_methods_tenant ON payment_methods(tenant_id);
CREATE INDEX idx_invoices_tenant_created_at ON invoices(tenant_id, created_at DESC);
CREATE INDEX idx_billing_events_tenant ON billing_events(tenant_id, created_at DESC);

-- Enable RLS
ALTER TABLE billing_plans ENABLE ROW LEVEL SECURITY;
ALTER TABLE subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE payment_methods ENABLE ROW LEVEL SECURITY;
ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE billing_events ENABLE ROW LEVEL SECURITY;

-- RLS policies (billing plans are global, not tenant-specific)
CREATE POLICY tenant_isolation_subscriptions ON subscriptions
    FOR ALL
    TO vault_app
    USING (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation_payment_methods ON payment_methods
    FOR ALL
    TO vault_app
    USING (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation_invoices ON invoices
    FOR ALL
    TO vault_app
    USING (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation_usage_records ON usage_records
    FOR ALL
    TO vault_app
    USING (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation_billing_events ON billing_events
    FOR ALL
    TO vault_app
    USING (tenant_id = current_tenant_id());

-- Triggers
CREATE TRIGGER update_billing_plans_updated_at BEFORE UPDATE ON billing_plans
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_subscriptions_updated_at BEFORE UPDATE ON subscriptions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_payment_methods_updated_at BEFORE UPDATE ON payment_methods
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Comments
COMMENT ON TABLE billing_plans IS 'Stripe product/price definitions';
COMMENT ON TABLE subscriptions IS 'Tenant subscription status linked to Stripe';
COMMENT ON TABLE payment_methods IS 'Stored payment methods from Stripe';
COMMENT ON TABLE invoices IS 'Invoice records synced from Stripe';
COMMENT ON TABLE usage_records IS 'Metered usage for billing';
COMMENT ON TABLE billing_events IS 'Audit log for billing events';
