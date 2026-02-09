-- Insert platform tenant for system-level audit logs

INSERT INTO tenants (id, slug, name, status)
VALUES ('00000000-0000-0000-0000-000000000001', 'platform', 'Platform', 'active')
ON CONFLICT (id) DO NOTHING;
