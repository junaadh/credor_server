//! Admin system logs endpoint with real-time log retrieval.
//!
//! Provides endpoints for retrieving and filtering system logs, error messages,
//! and audit trails for administrative monitoring and debugging purposes.

use crate::AppState;
use crate::auth_middleware::AuthMiddleware;
use crate::handlers::admin::guard::admin_guard;
use actix_web::{HttpResponse, Responder, web};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Individual log entry with metadata and context.
#[derive(Debug, Serialize)]
pub struct LogEntry {
    /// Unique identifier for this log entry
    pub id: Uuid,
    /// Timestamp when the log was created
    pub timestamp: DateTime<Utc>,
    /// Log level (ERROR, WARN, INFO, DEBUG)
    pub level: String,
    /// Source component or module that generated the log
    pub source: String,
    /// Log message content
    pub message: String,
    /// User ID if the log is related to a specific user action
    pub user_id: Option<Uuid>,
    /// Additional context data (JSON)
    pub context: Option<serde_json::Value>,
}

/// Response payload for admin logs with pagination info.
#[derive(Serialize)]
pub struct AdminLogsResponse {
    /// List of log entries
    pub logs: Vec<LogEntry>,
    /// Total number of logs matching the query
    pub total_count: i64,
    /// Number of logs returned in this response
    pub page_size: usize,
    /// Current page offset
    pub offset: i64,
}

/// Query parameters for log filtering and pagination.
#[derive(Debug, Deserialize)]
pub struct LogQuery {
    /// Log level filter (ERROR, WARN, INFO, DEBUG)
    pub level: Option<String>,
    /// Source component filter
    pub source: Option<String>,
    /// User ID filter for user-specific logs
    pub user_id: Option<Uuid>,
    /// Maximum number of logs to return (default: 100, max: 1000)
    pub limit: Option<i64>,
    /// Number of logs to skip for pagination (default: 0)
    pub offset: Option<i64>,
    /// Start date for time-based filtering (ISO 8601)
    pub start_date: Option<DateTime<Utc>>,
    /// End date for time-based filtering (ISO 8601)
    pub end_date: Option<DateTime<Utc>>,
}

/// Retrieves system logs with filtering and pagination support for admin monitoring.
///
/// This endpoint provides access to application logs, error messages, audit trails,
/// and system events for debugging and monitoring purposes. Supports various filters
/// for log level, source component, user actions, and time ranges.
///
/// # HTTP Method
/// `GET /api/admin/logs`
///
/// # Authentication
/// Requires valid JWT token with admin role in Authorization header:
/// ```
/// Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
/// ```
///
/// # Query Parameters
/// All parameters are optional for flexible log filtering:
/// - `level`: Filter by log level (ERROR, WARN, INFO, DEBUG)
/// - `source`: Filter by source component (auth, scan, api, etc.)
/// - `user_id`: Filter logs related to specific user UUID
/// - `limit`: Number of logs to return (default: 100, max: 1000)
/// - `offset`: Number of logs to skip for pagination (default: 0)
/// - `start_date`: Start date in ISO 8601 format (e.g., 2024-01-01T00:00:00Z)
/// - `end_date`: End date in ISO 8601 format
///
/// # Request Examples
/// ```
/// GET /api/admin/logs?level=ERROR&limit=50
/// GET /api/admin/logs?source=auth&start_date=2024-01-01T00:00:00Z
/// GET /api/admin/logs?user_id=123e4567-e89b-12d3-a456-426614174000
/// ```
///
/// # Success Response (200 OK)
/// Returns paginated log entries with metadata:
/// ```json
/// {
///   "logs": [
///     {
///       "id": "550e8400-e29b-41d4-a716-446655440000",
///       "timestamp": "2024-01-15T10:30:00Z",
///       "level": "ERROR",
///       "source": "scan_processor",
///       "message": "Failed to connect to detection model",
///       "user_id": null,
///       "context": {
///         "job_id": "abc123",
///         "retry_count": 3,
///         "error_code": "CONNECTION_TIMEOUT"
///       }
///     }
///   ],
///   "total_count": 1247,
///   "page_size": 50,
///   "offset": 0
/// }
/// ```
///
/// # Error Responses
/// - `401 Unauthorized`: Missing or invalid JWT token
/// - `403 Forbidden`: User lacks admin privileges
/// - `400 Bad Request`: Invalid query parameters (invalid dates, limits too high)
/// - `500 Internal Server Error`: Database query failures
///
/// # Authorization
/// Requires admin privileges verified through `admin_guard()`.
pub async fn get_admin_logs(
    user: AuthMiddleware,
    app_state: web::Data<AppState>,
    web::Query(query): web::Query<LogQuery>,
) -> impl Responder {
    if let Err(resp) = admin_guard(&user) {
        return resp;
    }

    // Validate and set default values with proper clamping
    let limit = query.limit.unwrap_or(100).clamp(1, 1000);
    let offset = query.offset.unwrap_or(0).max(0);

    // Validate log level if provided
    if let Some(ref level) = query.level {
        if !["ERROR", "WARN", "INFO", "DEBUG"].contains(&level.as_str()) {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid log level. Must be one of: ERROR, WARN, INFO, DEBUG"
            }));
        }
    }

    // Get total count with filtering
    let total_count = match get_logs_count(&app_state.db, &query).await {
        Ok(count) => count,
        Err(e) => {
            log::error!("Failed to get logs count: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve logs count"
            }));
        }
    };

    // Get filtered logs with pagination
    let logs = match get_filtered_logs(&app_state.db, &query, limit, offset).await {
        Ok(logs) => logs,
        Err(e) => {
            log::error!("Failed to get filtered logs: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve logs"
            }));
        }
    };

    HttpResponse::Ok().json(AdminLogsResponse {
        logs,
        total_count,
        page_size: limit as usize,
        offset,
    })
}

/// Gets the total count of logs matching the filter criteria.
async fn get_logs_count(db: &sqlx::PgPool, query: &LogQuery) -> Result<i64, sqlx::Error> {
    let count = sqlx::query_scalar!(
        r#"
        SELECT COUNT(*) as count
        FROM system_logs
        WHERE ($1::TEXT IS NULL OR level = $1)
        AND ($2::TEXT IS NULL OR source = $2)
        AND ($3::UUID IS NULL OR user_id = $3)
        AND ($4::TIMESTAMPTZ IS NULL OR timestamp >= $4)
        AND ($5::TIMESTAMPTZ IS NULL OR timestamp <= $5)
        "#,
        query.level.as_deref(),
        query.source.as_deref(),
        query.user_id,
        query.start_date,
        query.end_date
    )
    .fetch_one(db)
    .await?;

    Ok(count.unwrap_or(0))
}

/// Gets filtered and paginated logs from the database.
async fn get_filtered_logs(
    db: &sqlx::PgPool,
    query: &LogQuery,
    limit: i64,
    offset: i64,
) -> Result<Vec<LogEntry>, sqlx::Error> {
    let rows = sqlx::query!(
        r#"
        SELECT
            id,
            timestamp,
            level,
            source,
            message,
            user_id,
            context
        FROM system_logs
        WHERE ($1::TEXT IS NULL OR level = $1)
        AND ($2::TEXT IS NULL OR source = $2)
        AND ($3::UUID IS NULL OR user_id = $3)
        AND ($4::TIMESTAMPTZ IS NULL OR timestamp >= $4)
        AND ($5::TIMESTAMPTZ IS NULL OR timestamp <= $5)
        ORDER BY timestamp DESC
        LIMIT $6 OFFSET $7
        "#,
        query.level.as_deref(),
        query.source.as_deref(),
        query.user_id,
        query.start_date,
        query.end_date,
        limit,
        offset
    )
    .fetch_all(db)
    .await?;

    let logs: Vec<LogEntry> = rows
        .into_iter()
        .map(|row| LogEntry {
            id: row.id,
            timestamp: row.timestamp,
            level: row.level,
            source: row.source,
            message: row.message,
            user_id: row.user_id,
            context: row.context,
        })
        .collect();

    Ok(logs)
}

/// Helper function to create a new log entry in the database.
/// This can be used by other parts of the application to log events.
pub async fn create_system_log_entry(
    db: &sqlx::PgPool,
    level: &str,
    source: &str,
    message: &str,
    user_id: Option<Uuid>,
    context: Option<serde_json::Value>,
) -> Result<Uuid, sqlx::Error> {
    let log_id = sqlx::query_scalar!(
        r#"
        INSERT INTO system_logs (level, source, message, user_id, context)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id
        "#,
        level,
        source,
        message,
        user_id,
        context
    )
    .fetch_one(db)
    .await?;

    Ok(log_id)
}

/// Convenience macro for logging events to the database.
///
/// # Usage
/// ```rust
/// log_to_system_db!(pool, "ERROR", "auth_service", "Login failed", Some(user_id), json!({"ip": "192.168.1.1"}));
/// log_to_system_db!(pool, "INFO", "scan_processor", "Scan completed successfully", None, None);
/// ```
#[macro_export]
macro_rules! log_to_system_db {
    ($db:expr, $level:expr, $source:expr, $message:expr, $user_id:expr, $context:expr) => {
        tokio::spawn(async move {
            if let Err(e) = crate::handlers::admin::logs::create_system_log_entry(
                $db, $level, $source, $message, $user_id, $context,
            )
            .await
            {
                eprintln!("Failed to write to system logs: {}", e);
            }
        });
    };
}
