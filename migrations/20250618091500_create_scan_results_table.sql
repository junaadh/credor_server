CREATE TABLE IF NOT EXISTS scan_results (
    result_id UUID PRIMARY KEY,
    job_id UUID REFERENCES scan_jobs(job_id),
    user_id UUID NOT NULL REFERENCES user_profiles(user_id),
    media_url TEXT,
    confidence FLOAT,
    label TEXT,
    detected_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE scan_results ENABLE ROW LEVEL SECURITY;
CREATE POLICY user_rw_own ON scan_results
  FOR ALL
  USING (user_id = auth.uid())
  WITH CHECK (user_id = auth.uid());
CREATE POLICY admin_rw_all_scan_results ON scan_results
  FOR ALL
  USING (auth.jwt() -> 'user_metadata' ->> 'role' = 'admin')
  WITH CHECK (auth.jwt() -> 'user_metadata' ->> 'role' = 'admin');
REVOKE ALL ON scan_results FROM PUBLIC;


