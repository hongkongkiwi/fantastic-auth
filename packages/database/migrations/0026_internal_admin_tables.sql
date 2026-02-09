-- Internal admin data tables (admin API keys, notifications, support)

-- Admin API keys (separate from M2M service account keys)
CREATE TABLE IF NOT EXISTS admin_api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    prefix TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    scopes TEXT[] NOT NULL DEFAULT '{}',
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_admin_api_keys_tenant ON admin_api_keys(tenant_id);
CREATE INDEX IF NOT EXISTS idx_admin_api_keys_created ON admin_api_keys(created_at);

ALTER TABLE admin_api_keys ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_admin_api_keys ON admin_api_keys
    USING (tenant_id = current_setting('app.current_tenant_id')::UUID);

-- Notifications
CREATE TABLE IF NOT EXISTS notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    type TEXT NOT NULL,
    read BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_notifications_tenant ON notifications(tenant_id);
CREATE INDEX IF NOT EXISTS idx_notifications_created ON notifications(created_at);

ALTER TABLE notifications ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_notifications ON notifications
    USING (tenant_id = current_setting('app.current_tenant_id')::UUID);

-- Support tickets
CREATE TABLE IF NOT EXISTS support_tickets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    subject TEXT NOT NULL,
    status TEXT NOT NULL,
    priority TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_support_tickets_tenant ON support_tickets(tenant_id);
CREATE INDEX IF NOT EXISTS idx_support_tickets_updated ON support_tickets(updated_at);

ALTER TABLE support_tickets ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_support_tickets ON support_tickets
    USING (tenant_id = current_setting('app.current_tenant_id')::UUID);

-- Support incidents
CREATE TABLE IF NOT EXISTS support_incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_support_incidents_tenant ON support_incidents(tenant_id);
CREATE INDEX IF NOT EXISTS idx_support_incidents_started ON support_incidents(started_at);

ALTER TABLE support_incidents ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_support_incidents ON support_incidents
    USING (tenant_id = current_setting('app.current_tenant_id')::UUID);

-- Service status
CREATE TABLE IF NOT EXISTS service_status (
    service TEXT PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    status TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_service_status_tenant ON service_status(tenant_id);

ALTER TABLE service_status ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_service_status ON service_status
    USING (tenant_id = current_setting('app.current_tenant_id')::UUID);

-- Seed data for new tables (only when empty per tenant)
INSERT INTO notifications (tenant_id, title, description, type, read, created_at)
SELECT t.id,
       v.title,
       v.description,
       v.type,
       false,
       NOW() - v.age::interval
FROM tenants t
CROSS JOIN (
    VALUES
        ('Billing webhook failed', 'Stripe webhook endpoint returned 500 for tenant Acme Inc.', 'warning', '2 hours'),
        ('New admin added', 'Jamie Liu was granted Platform Admin role.', 'success', '4 hours')
) AS v(title, description, type, age)
WHERE NOT EXISTS (
    SELECT 1 FROM notifications n WHERE n.tenant_id = t.id
);

INSERT INTO support_tickets (tenant_id, subject, status, priority, updated_at, created_at)
SELECT t.id,
       v.subject,
       v.status,
       v.priority,
       NOW() - v.updated_age::interval,
       NOW() - v.created_age::interval
FROM tenants t
CROSS JOIN (
    VALUES
        ('Login failures for tenant Acme Inc', 'open', 'high', '45 minutes', '6 hours'),
        ('Webhook retry delays', 'pending', 'medium', '2 hours', '12 hours')
) AS v(subject, status, priority, updated_age, created_age)
WHERE NOT EXISTS (
    SELECT 1 FROM support_tickets s WHERE s.tenant_id = t.id
);

INSERT INTO support_incidents (tenant_id, title, status, started_at, created_at)
SELECT t.id,
       v.title,
       v.status,
       NOW() - v.started_age::interval,
       NOW() - v.created_age::interval
FROM tenants t
CROSS JOIN (
    VALUES
        ('Email delivery delays', 'monitoring', '1 day', '1 day'),
        ('API latency spike', 'resolved', '2 days', '2 days')
) AS v(title, status, started_age, created_age)
WHERE NOT EXISTS (
    SELECT 1 FROM support_incidents s WHERE s.tenant_id = t.id
);

INSERT INTO service_status (service, tenant_id, status, updated_at)
SELECT v.service,
       t.id,
       v.status,
       NOW()
FROM tenants t
CROSS JOIN (
    VALUES
        ('API', 'operational'),
        ('Auth', 'degraded'),
        ('Billing', 'operational')
) AS v(service, status)
WHERE NOT EXISTS (
    SELECT 1 FROM service_status s WHERE s.tenant_id = t.id AND s.service = v.service
);
