-- Add migration script here
CREATE TABLE encodings (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES user_profiles(user_id),
    key TEXT NOT NULL,
    encoding BYTEA,
    created_at TIMESTAMPTZ DEFAULT now(),
    UNIQUE (user_id, key)
);
