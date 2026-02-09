-- Add updated_at to sessions for parity with repository expectations
ALTER TABLE IF EXISTS sessions
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
