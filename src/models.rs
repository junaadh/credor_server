//! Data models for users, scan jobs, and settings.
//!
//! This module defines all serializable structs used for DB access and API responses.
//! Models derive Serde and SQLx traits for easy (de)serialization and DB mapping.

use std::{env, sync::Arc};

use chrono;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::db;

/// Represents a user in the system.
#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    /// User's unique identifier
    pub id: Uuid,
    /// User's email address
    pub email: String,
}

/// Represents a scan job history entry for a user.
///
/// This structure tracks the historical record of scan operations performed
/// by users in the system. It provides a lightweight view of scan activity
/// for displaying user history and audit trails.
///
/// # Database Mapping
///
/// This struct maps to scan job records in the database, providing essential
/// information for history displays without the full job details.
///
/// # Usage
///
/// Typically used in:
/// - User dashboard history views
/// - Audit logging and tracking
/// - Quick scan summaries
/// - Timeline displays
#[derive(Debug, Serialize, Deserialize)]
pub struct ScanHistory {
    /// Scan job ID
    /// Unique identifier linking to the full scan job record
    pub id: Uuid,
    /// User who initiated the scan
    /// References the user_profiles.user_id field
    pub user_id: Uuid,
    /// When the scan was performed
    /// Timestamp of scan initiation for chronological ordering
    pub scanned_at: chrono::NaiveDateTime,
}

/// User settings/preferences for the UI and scan defaults.
///
/// This structure stores user-customizable application settings and preferences.
/// All fields except email are optional, allowing users to customize their
/// experience while maintaining sensible defaults.
///
/// # JSON Fields
///
/// The `scan_defaults` and `notifications` fields use JSON for flexible
/// schema-less storage of complex preference objects.
///
/// # Database Integration
///
/// Uses SQLx's `FromRow` derive for automatic mapping from database rows,
/// making it easy to query and update user preferences.
///
/// # Examples
///
/// ```json
/// {
///   "scan_defaults": {
///     "confidence_threshold": 0.8,
///     "notify_on_completion": true,
///     "auto_delete_after_days": 30
///   },
///   "notifications": {
///     "email_alerts": true,
///     "push_notifications": false,
///     "weekly_summary": true
///   }
/// }
/// ```
#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct UserSettings {
    /// User's email
    /// Primary identifier linking to the user account
    pub email: String,
    /// Default scan parameters (JSON)
    /// Flexible JSON storage for user's preferred scan configurations
    pub scan_defaults: Option<serde_json::Value>,
    /// UI theme (e.g., dark/light)
    /// Controls the visual appearance of the user interface
    pub theme: Option<String>,
    /// Notification preferences (JSON)
    /// JSON object defining when and how to notify the user
    pub notifications: Option<serde_json::Value>,
    /// Preferred language
    /// ISO language code for interface localization (e.g., "en", "es", "fr")
    pub language: Option<String>,
    /// Preferred timezone
    /// IANA timezone identifier for timestamp display (e.g., "America/New_York")
    pub timezone: Option<String>,
}

/// Shared application state for all handlers.
///
/// Holds the SQLx Postgres connection pool and Supabase credentials.
#[derive(Clone)]
pub struct AppState {
    /// SQLx Postgres connection pool
    pub db: Arc<sqlx::PgPool>,
    /// Supabase REST API URL
    pub supabase_url: String,
    /// Supabase service key for JWT validation
    pub supabase_service_key: String,
    /// Supabase service key for JWT validation
    pub supabase_anon_key: String,
    /// Supabase JWT secret for auth
    pub supabase_jwt_secret: String,
}

impl AppState {
    /// Creates a new AppState instance with database connection and Supabase configuration.
    ///
    /// This constructor reads all required configuration from environment variables
    /// and establishes a connection pool to the PostgreSQL database. It validates
    /// that all necessary Supabase credentials are present.
    ///
    /// # Environment Variables
    ///
    /// The following environment variables must be set:
    /// - `SUPABASE_URL`: Base URL for Supabase API
    /// - `SUPABASE_SERVICE_KEY`: Service role key for admin operations
    /// - `SUPABASE_ANON_KEY`: Anonymous key for client operations
    /// - `SUPABASE_JWT_SECRET`: Secret for JWT token validation
    /// - `DATABASE_URL`: PostgreSQL connection string (used by db::connect_pg_pool)
    ///
    /// # Returns
    ///
    /// * `Ok(AppState)` - Successfully configured application state
    /// * `Err(anyhow::Error)` - Configuration error or database connection failure
    ///
    /// # Errors
    ///
    /// This function will panic if any required environment variables are missing.
    /// Database connection errors are returned as `anyhow::Error`.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use crate::models::AppState;
    ///
    /// #[tokio::main]
    /// async fn main() -> anyhow::Result<()> {
    ///     let app_state = AppState::new().await?;
    ///     println!("Connected to database with {} connections",
    ///              app_state.db.size());
    ///     Ok(())
    /// }
    /// ```
    pub async fn new() -> anyhow::Result<Self> {
        let supabase_url = env::var("SUPABASE_URL").expect("SUPABASE_URL must be set");
        let supabase_service_key =
            env::var("SUPABASE_SERVICE_KEY").expect("SUPABASE_SERVICE_KEY must be set");

        let supabase_anon_key =
            env::var("SUPABASE_ANON_KEY").expect("SUPABASE_ANON_KEY must be set");
        let supabase_jwt_secret =
            env::var("SUPABASE_JWT_SECRET").expect("SUPABASE_JWT_SECRET must be set");
        let db = db::connect_pg_pool().await;

        Ok(Self {
            db: Arc::new(db),
            supabase_url,
            supabase_service_key,
            supabase_anon_key,
            supabase_jwt_secret,
        })
    }
}
