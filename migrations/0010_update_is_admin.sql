-- Expand admin role check to include service role

CREATE OR REPLACE FUNCTION is_admin()
RETURNS BOOLEAN AS $$
DECLARE
    user_role TEXT;
BEGIN
    user_role := current_setting('app.current_user_role', TRUE);
    RETURN user_role = 'admin' OR user_role = 'owner' OR user_role = 'service';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
