//! Database writer for persisting application logs to the system_logs table.
//!
//! This module provides a custom tracing layer that writes logs directly to PostgreSQL
//! for persistence, audit trails, and advanced log analysis. Works alongside stdout
//! logging to provide comprehensive observability.

use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::PgPool;
use std::{str::FromStr, sync::Arc};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::{Context, Layer};
use uuid::Uuid;

#[allow(async_fn_in_trait)]
pub trait DatabaseWriter: Send + Sync + 'static {
    async fn write_log(
        &self,
        level: &str,
        source: &str,
        message: &str,
        user_id: Option<Uuid>,
        context: Option<Value>,
    ) -> Result<Uuid, sqlx::Error>;
    async fn cleanup_old_logs(&self, retention_days: i32) -> Result<u64, sqlx::Error>;
    fn get_pool_info(&self) -> PoolInfo;
    async fn write_logs_batch(&self, entries: Vec<LogEntry>) -> Result<Vec<Uuid>, sqlx::Error>;
}

impl DatabaseWriter for Arc<PgPool> {
    /// Write a log entry to the database.
    ///
    /// This method performs the actual database insertion with proper error handling.
    /// It's designed to be non-blocking and resilient to database connectivity issues.
    ///
    /// # Arguments
    /// * `level` - Log level (ERROR, WARN, INFO, DEBUG)
    /// * `source` - Source component or module
    /// * `message` - Log message content
    /// * `user_id` - Optional user ID associated with the log
    /// * `context` - Additional structured context data
    async fn write_log(
        &self,
        level: &str,
        source: &str,
        message: &str,
        user_id: Option<Uuid>,
        context: Option<Value>,
    ) -> Result<Uuid, sqlx::Error> {
        let log_id = sqlx::query_scalar!(
            r#"
            INSERT INTO system_logs (level, source, message, user_id, context, timestamp)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id
            "#,
            level,
            source,
            message,
            user_id,
            context,
            Utc::now()
        )
        .fetch_one(self.as_ref())
        .await?;

        Ok(log_id)
    }

    /// Write multiple log entries in a batch operation.
    ///
    /// This method is optimized for high-throughput logging scenarios where
    /// multiple log entries need to be persisted efficiently.
    async fn write_logs_batch(&self, entries: Vec<LogEntry>) -> Result<Vec<Uuid>, sqlx::Error> {
        let mut tx = self.begin().await?;
        let mut ids = Vec::new();

        for entry in entries {
            let id = sqlx::query_scalar!(
                r#"
                INSERT INTO system_logs (level, source, message, user_id, context, timestamp)
                VALUES ($1, $2, $3, $4, $5, $6)
                RETURNING id
                "#,
                entry.level,
                entry.source,
                entry.message,
                entry.user_id,
                entry.context,
                entry.timestamp
            )
            .fetch_one(&mut *tx)
            .await?;

            ids.push(id);
        }

        tx.commit().await?;
        Ok(ids)
    }

    /// Clean up old log entries based on retention policy.
    ///
    /// This method should be called periodically to maintain database performance
    /// by removing logs older than the specified retention period.
    async fn cleanup_old_logs(&self, retention_days: i32) -> Result<u64, sqlx::Error> {
        let cutoff_date = Utc::now() - chrono::Duration::days(retention_days as i64);

        let result = sqlx::query!(
            r#"
            DELETE FROM system_logs
            WHERE timestamp < $1
            "#,
            cutoff_date
        )
        .execute(self.as_ref())
        .await?;

        Ok(result.rows_affected())
    }

    /// Get database connection pool statistics for monitoring.
    fn get_pool_info(&self) -> PoolInfo {
        PoolInfo {
            size: self.size(),
            idle: self.num_idle(),
        }
    }
}

/// Log entry structure for batch operations.
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub level: String,
    pub source: String,
    pub message: String,
    pub user_id: Option<Uuid>,
    pub context: Option<Value>,
    pub timestamp: DateTime<Utc>,
}

impl LogEntry {
    /// Create a new log entry with current timestamp.
    pub fn new(
        level: String,
        source: String,
        message: String,
        user_id: Option<Uuid>,
        context: Option<Value>,
    ) -> Self {
        Self {
            level,
            source,
            message,
            user_id,
            context,
            timestamp: Utc::now(),
        }
    }
}

/// Database connection pool information.
#[derive(Debug)]
pub struct PoolInfo {
    pub size: u32,
    pub idle: usize,
}
/// Custom tracing layer that writes to database.
///
/// This layer integrates with the tracing ecosystem to automatically
/// capture and persist log events to the database.
// pub struct DatabaseLayer {
//     writer: Arc<PgPool>,
// }

// impl DatabaseLayer {
//     /// Create a new database layer with the given writer.
//     pub fn new(writer: Arc<PgPool>) -> Self {
//         Self { writer }
//     }
// }

// impl<S> Layer<S> for DatabaseLayer
// where
//     S: Subscriber + for<'lookup> tracing_subscriber::registry::LookupSpan<'lookup>,
// {
//     fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
//         let level = event.metadata().level().to_string().to_uppercase();
//         let target = event.metadata().target();

//         // Extract fields from the event
//         let mut visitor = EventVisitor::new();
//         event.record(&mut visitor);

//         let message = visitor.message.unwrap_or_else(|| "No message".to_string());
//         let user_id = visitor.user_id;
//         let context = visitor.context;

//         // Spawn async task to write to database
//         let writer = self.writer.clone();
//         tokio::spawn(async move {
//             if let Err(e) = writer
//                 .write_log(&level, target, &message, user_id, context)
//                 .await
//             {
//                 // Use eprintln to avoid infinite recursion with tracing
//                 eprintln!("Failed to write log to database: {e}");
//             }
//         });
//     }
// }

/// Visitor for extracting fields from tracing events.
// struct EventVisitor {
//     message: Option<String>,
//     user_id: Option<Uuid>,
//     context: Option<Value>,
// }

// impl EventVisitor {
//     fn new() -> Self {
//         Self {
//             message: None,
//             user_id: None,
//             context: None,
//         }
//     }
// }

// impl tracing::field::Visit for EventVisitor {
//     fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
//         match field.name() {
//             "message" => {
//                 self.message = Some(format!("{:?}", value));
//             }
//             "event.user_id" => {
//                 // Try to parse the debug representation as UUID
//                 let debug_str = format!("{:?}", value);
//                 if let Ok(uuid) = debug_str.trim_matches('"').parse::<Uuid>() {
//                     self.user_id = Some(uuid);
//                 }
//             }
//             "event.context" => {
//                 // Try to parse the debug representation as JSON
//                 let debug_str = format!("{:?}", value);
//                 if let Ok(json) = serde_json::from_str::<Value>(&debug_str) {
//                     self.context = Some(json);
//                 }
//             }
//             _ => {}
//         }
//     }

//     fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
//         match field.name() {
//             "message" => {
//                 self.message = Some(value.to_string());
//             }
//             "user_id" => {
//                 self.user_id = Uuid::from_str(value).ok();
//             }
//             _ => {}
//         }
//     }
// }

// /// Async task for periodic log cleanup.
// pub async fn start_log_cleanup_task(writer: Arc<PgPool>, retention_days: i32) {
//     let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(86400)); // 24 hours

//     loop {
//         interval.tick().await;

//         match writer.cleanup_old_logs(retention_days).await {
//             Ok(deleted_count) => {
//                 tracing::info!(
//                     deleted_count = deleted_count,
//                     retention_days = retention_days,
//                     "Log cleanup completed"
//                 );
//             }
//             Err(e) => {
//                 tracing::error!(
//                     error = %e,
//                     "Failed to cleanup old logs"
//                 );
//             }
//         }
//     }
// }

/// Helper function to validate log levels.
pub fn is_valid_log_level(level: &str) -> bool {
    matches!(level, "ERROR" | "WARN" | "INFO" | "DEBUG" | "TRACE")
}

/// Helper function to truncate long messages for database storage.
pub fn truncate_message(message: &str, max_length: usize) -> String {
    if message.len() <= max_length {
        message.to_string()
    } else {
        format!("{}... [truncated]", &message[..max_length - 15])
    }
}

/// Performance monitor for database writer operations.
#[derive(Debug, Default)]
pub struct DatabaseWriterMetrics {
    pub writes_total: u64,
    pub writes_failed: u64,
    pub batch_writes_total: u64,
    pub avg_write_duration_ms: f64,
}

impl DatabaseWriterMetrics {
    /// Record a successful write operation.
    pub fn record_write_success(&mut self, duration_ms: f64) {
        self.writes_total += 1;
        self.avg_write_duration_ms = (self.avg_write_duration_ms * (self.writes_total - 1) as f64
            + duration_ms)
            / self.writes_total as f64;
    }

    /// Record a failed write operation.
    pub fn record_write_failure(&mut self) {
        self.writes_failed += 1;
    }

    /// Record a batch write operation.
    pub fn record_batch_write(&mut self) {
        self.batch_writes_total += 1;
    }

    /// Get the write success rate.
    pub fn success_rate(&self) -> f64 {
        if self.writes_total == 0 {
            0.0
        } else {
            (self.writes_total - self.writes_failed) as f64 / self.writes_total as f64
        }
    }
}
