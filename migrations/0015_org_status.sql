-- Add organization status column (for admin status updates)
ALTER TABLE IF EXISTS organizations
    ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active';
