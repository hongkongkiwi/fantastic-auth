-- Additional RLS policies for existing tables

-- Organization invitations
CREATE POLICY tenant_isolation_org_invitations ON organization_invitations
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id());

-- Rate limits
CREATE POLICY tenant_isolation_rate_limits ON rate_limits
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id());

-- Billing plans are global (read-only for tenant app role)
CREATE POLICY billing_plans_read_only ON billing_plans
    FOR SELECT TO vault_app
    USING (true);
