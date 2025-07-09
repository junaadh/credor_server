-- Add migration script here

CREATE TABLE IF NOT EXISTS user_profiles (
    user_id UUID PRIMARY KEY,
    name TEXT,
    age INT,
    gender TEXT
);

ALTER TABLE user_profiles ENABLE ROW LEVEL SECURITY;
CREATE POLICY user_rw_own ON user_profiles
  FOR ALL
  USING (user_id = auth.uid())
  WITH CHECK (user_id = auth.uid());
CREATE POLICY admin_rw_all_user_profiles ON user_profiles
  FOR ALL
  USING (auth.jwt() -> 'user_metadata' ->> 'role' = 'admin')
  WITH CHECK (auth.jwt() -> 'user_metadata' ->> 'role' = 'admin');
REVOKE ALL ON user_profiles FROM PUBLIC;
