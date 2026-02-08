-- Development-only convenience: set vault_app password
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vault_app') THEN
        ALTER ROLE vault_app WITH PASSWORD 'vault';
    END IF;
END
$$;
