-- Add migration script here

CREATE TABLE IF NOT EXISTS scan_jobs (
    job_id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES user_profiles(user_id),
    target TEXT NOT NULL,
    notes TEXT,
    priority TEXT,
    status TEXT,
    timestamp TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_user_id ON scan_jobs(user_id);

ALTER TABLE scan_jobs ENABLE ROW LEVEL SECURITY;
CREATE POLICY user_rw_own ON scan_jobs
  FOR ALL
  USING (user_id = auth.uid())
  WITH CHECK (user_id = auth.uid());
CREATE POLICY admin_rw_all_scan_jobs ON scan_jobs
  FOR ALL
  USING (auth.jwt() -> 'user_metadata' ->> 'role' = 'admin')
  WITH CHECK (auth.jwt() -> 'user_metadata' ->> 'role' = 'admin');
REVOKE ALL ON scan_jobs FROM PUBLIC;
