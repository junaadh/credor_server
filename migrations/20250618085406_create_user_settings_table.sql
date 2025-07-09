-- Add migration script here

CREATE TABLE IF NOT EXISTS user_settings (
    user_id UUID PRIMARY KEY REFERENCES user_profiles(user_id),
    email TEXT NOT NULL,
    scan_defaults JSONB NOT NULL,
    theme TEXT DEFAULT 'system',
    notifications JSONB DEFAULT '{}'::jsonb,
    language TEXT DEFAULT 'en',
    timezone TEXT DEFAULT 'UTC',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE user_settings ENABLE ROW LEVEL SECURITY;
CREATE POLICY user_rw_own ON user_settings
  FOR ALL
  USING (user_id = auth.uid())
  WITH CHECK (user_id = auth.uid());
CREATE POLICY admin_rw_all_user_settings ON user_settings
  FOR ALL
  USING (auth.jwt() -> 'user_metadata' ->> 'role' = 'admin')
  WITH CHECK (auth.jwt() -> 'user_metadata' ->> 'role' = 'admin');
REVOKE ALL ON user_settings FROM PUBLIC;
