//! Database connection utilities for the credor backend.
//!
//! Provides a function to create a connection pool to the Postgres database using environment variables.

use sqlx::{PgPool, postgres::PgPoolOptions};
use std::env;

/// Establishes a connection pool to the Postgres database using the `DATABASE_URL` environment variable.
///
/// # Panics
/// Panics if the `DATABASE_URL` is not set or if the connection fails.
///
/// # Returns
/// A [`PgPool`] instance for use with SQLx queries.
pub async fn connect_pg_pool() -> PgPool {
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to create Postgres pool")
}
