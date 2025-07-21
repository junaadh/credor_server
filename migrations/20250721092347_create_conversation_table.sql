-- Add migration script here
CREATE TABLE post_images (
    id SERIAL PRIMARY KEY,
    job_id UUID REFERENCES scan_jobs(job_id),
    post_uri TEXT,
    author_handle TEXT,
    image_url TEXT
);
