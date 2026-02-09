-- Allow app role to manage tenants (needed for internal flows/tests)
GRANT SELECT, INSERT, UPDATE ON tenants TO vault_app;
