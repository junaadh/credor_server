-- Add migration script here
-- Create system_logs table
CREATE TABLE IF NOT EXISTS system_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT now(),
    level TEXT NOT NULL CHECK (level IN ('ERROR', 'WARN', 'INFO', 'DEBUG')),
    source TEXT NOT NULL,
    message TEXT NOT NULL,
    user_id UUID REFERENCES user_profiles(user_id),
    context JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON system_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_logs_level ON system_logs(level);
CREATE INDEX IF NOT EXISTS idx_logs_source ON system_logs(source);
CREATE INDEX IF NOT EXISTS idx_logs_user_id ON system_logs(user_id);

-- Enable Row-Level Security
ALTER TABLE system_logs ENABLE ROW LEVEL SECURITY;

-- Admin full access policy
CREATE POLICY admin_rw_all_system_logs
  ON system_logs
  FOR ALL
  USING (auth.jwt() -> 'user_metadata' ->> 'role' = 'admin')
  WITH CHECK (auth.jwt() -> 'user_metadata' ->> 'role' = 'admin');

-- Optional: Users can SELECT logs related to them (read-only)
CREATE POLICY user_read_own_logs
  ON system_logs
  FOR SELECT
  USING (user_id = auth.uid());

-- Revoke default public access
REVOKE ALL ON system_logs FROM PUBLIC;
