//! Comprehensive tracing and logging infrastructure for the Credor application.
//!
//! This module provides:
//! - Dual logging to stdout and database
//! - Structured logging with context
//! - Request/response middleware
//! - User action tracking
//! - Error and event correlation

pub mod db_writer;
pub mod middleware;
pub mod utils;

use actix_web::web;
use serde_json::Value;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

/// Database writer for persisting logs to system_logs table
pub use db_writer::DatabaseWriter;

/// Request logging middleware
pub use middleware::RequestLoggingMiddleware;

/// Utility functions for enhanced logging
pub use utils::*;

// /// Initialize the tracing infrastructure with stdout and database logging.
// ///
// /// This function sets up:
// /// - Console logging with human-readable format
// /// - Database logging for persistence
// /// - Environment-based log level filtering
// /// - JSON formatting for structured logs
// pub async fn init_tracing(db_pool: Arc<PgPool>, cfg: &mut web::ServiceConfig) -> Result<()> {
//     // Create database writer using the shared pool
//     let db_writer = db_pool.clone();
//     // Register the database writer as app data
//     cfg.app_data(web::Data::from(db_writer));

//     tracing::info!(
//         system.event = "tracing_initialized",
//         system.stdout_enabled = true,
//         system.database_enabled = true,
//         "Tracing infrastructure initialized successfully"
//     );

//     Ok(())
// }

/// Log an event to both stdout and database with structured context.
///
/// This is the primary function for logging application events with full context.
///
/// # Arguments
/// * `level` - Log level (ERROR, WARN, INFO, DEBUG)
/// * `source` - Source component generating the log
/// * `message` - Human-readable log message
/// * `user_id` - Optional user ID associated with the event
/// * `context` - Additional structured context data
///
/// # Examples
/// ```rust
/// use serde_json::json;
///
/// log_event(
///     "INFO",
///     "auth_service",
///     "User login successful",
///     Some(user_id),
///     Some(json!({
///         "ip_address": "192.168.1.100",
///         "user_agent": "Mozilla/5.0...",
///         "session_id": "abc123"
///     }))
/// ).await;
/// ```
pub async fn log_event(
    db_writer: Arc<PgPool>,
    level: &str,
    source: &str,
    message: &str,
    user_id: Option<Uuid>,
    context: Option<Value>,
) {
    let context = sanitize_context(context);

    // Log to stdout using tracing
    match level {
        "ERROR" => tracing::error!(
            event.source = source,
            event.user_id = ?user_id,
            event.context = ?context,
            "{}", message
        ),
        "WARN" => tracing::warn!(
            event.source = source,
            event.user_id = ?user_id,
            event.context = ?context,
            "{}", message
        ),
        "INFO" => tracing::info!(
            event.source = source,
            event.user_id = ?user_id,
            event.context = ?context,
            "{}", message
        ),
        "DEBUG" => tracing::debug!(
            event.source = source,
            event.user_id = ?user_id,
            event.context = ?context,
            "{}", message
        ),
        _ => tracing::info!(
            event.source = source,
            event.user_id = ?user_id,
            event.context = ?context,
            level = level,
            "{}", message
        ),
    }

    // Also log to database
    if let Err(e) = db_writer
        .write_log(level, source, message, user_id, context)
        .await
    {
        tracing::error!(
            error = %e,
            "Failed to write log to database"
        );
    }
}

/// Log a user action with automatic context extraction.
///
/// This function is specifically designed for tracking user actions
/// with enhanced context including request metadata.

/// Log a user action with automatic context extraction.
pub async fn log_user_action(
    db_writer: Arc<PgPool>,
    action: &str,
    user_id: Uuid,
    details: Option<Value>,
    request_context: Option<Value>,
) {
    let mut context = serde_json::json!({
        "action": action,
        "details": details
    });

    if let Some(req_ctx) = request_context {
        context
            .as_object_mut()
            .unwrap()
            .extend(req_ctx.as_object().unwrap().clone());
    }

    log_event(
        db_writer,
        "INFO",
        "user_action",
        &format!("User action: {}", action),
        Some(user_id),
        Some(context),
    )
    .await;
}

/// Log a system error with full context and error details.
pub async fn log_system_error(
    db_writer: Arc<PgPool>,
    source: &str,
    error: &dyn std::error::Error,
    context: Option<Value>,
    user_id: Option<Uuid>,
) {
    let error_context = serde_json::json!({
        "error_type": std::any::type_name_of_val(error),
        "error_message": error.to_string(),
        "error_source": error.source().map(|s| s.to_string()),
        "additional_context": context
    });

    log_event(
        db_writer,
        "ERROR",
        source,
        &format!("System error: {}", error),
        user_id,
        Some(error_context),
    )
    .await;
}

pub async fn log_security_event(
    db_writer: Arc<PgPool>,
    event_type: &str,
    description: &str,
    user_id: Option<Uuid>,
    ip_address: Option<&str>,
    additional_context: Option<Value>,
) {
    let mut context = serde_json::json!({
        "security_event_type": event_type,
        "ip_address": ip_address,
        "timestamp": chrono::Utc::now(),
        "severity": "HIGH"
    });

    if let Some(additional) = additional_context {
        context
            .as_object_mut()
            .unwrap()
            .extend(additional.as_object().unwrap().clone());
    }

    log_event(
        db_writer,
        "WARN",
        "security",
        &format!("Security event: {} - {}", event_type, description),
        user_id,
        Some(context),
    )
    .await;
}

/// Log performance metrics and timing information.
pub async fn log_performance_metric(
    db_writer: Arc<PgPool>,
    operation: &str,
    duration_ms: u64,
    user_id: Option<Uuid>,
    additional_metrics: Option<Value>,
) {
    let context = serde_json::json!({
        "operation": operation,
        "duration_ms": duration_ms,
        "performance_category": categorize_performance(duration_ms),
        "additional_metrics": additional_metrics
    });

    let level = if duration_ms > 5000 { "WARN" } else { "INFO" };

    log_event(
        db_writer,
        level,
        "performance",
        &format!("Operation {} completed in {}ms", operation, duration_ms),
        user_id,
        Some(context),
    )
    .await;
}

/// Configure the application with tracing middleware.
pub fn configure_tracing_middleware(cfg: &mut web::ServiceConfig) {
    cfg.app_data(web::Data::new(middleware::RequestLoggingMiddleware::new()));
}

/// Convenience macro for logging with automatic source detection.
#[macro_export]
macro_rules! log_event {
    ($level:expr, $message:expr) => {
        $crate::tracing::log_event($level, module_path!(), $message, None, None).await
    };
    ($level:expr, $message:expr, $user_id:expr) => {
        $crate::tracing::log_event($level, module_path!(), $message, $user_id, None).await
    };
    ($level:expr, $message:expr, $user_id:expr, $context:expr) => {
        $crate::tracing::log_event($level, module_path!(), $message, $user_id, Some($context)).await
    };
}

/// Convenience macro for user action logging.
#[macro_export]
macro_rules! log_user_action {
    ($action:expr, $user_id:expr) => {
        $crate::tracing::log_user_action($action, $user_id, None, None).await
    };
    ($action:expr, $user_id:expr, $details:expr) => {
        $crate::tracing::log_user_action($action, $user_id, Some($details), None).await
    };
    ($action:expr, $user_id:expr, $details:expr, $context:expr) => {
        $crate::tracing::log_user_action($action, $user_id, Some($details), Some($context)).await
    };
}

/// Helper function to categorize performance based on duration.
fn categorize_performance(duration_ms: u64) -> &'static str {
    match duration_ms {
        0..=100 => "EXCELLENT",
        101..=500 => "GOOD",
        501..=2000 => "ACCEPTABLE",
        2001..=5000 => "SLOW",
        _ => "CRITICAL",
    }
}

/// Sanitize context to remove sensitive information.
fn sanitize_context(context: Option<Value>) -> Option<Value> {
    let mut context = context?;

    if let Some(obj) = context.as_object_mut() {
        // Remove or redact sensitive fields
        let sensitive_fields = [
            "password",
            "token",
            "secret",
            "key",
            "authorization",
            "cookie",
            "session",
            "refresh_token",
            "access_token",
        ];

        for field in &sensitive_fields {
            if obj.contains_key(*field) {
                obj.insert(field.to_string(), serde_json::json!("[REDACTED]"));
            }
        }
    }

    Some(context)
}
