//! Application-wide structured logging implementation.
//!
//! This module provides a custom logging system that:
//! - Outputs structured JSON logs to stdout for observability
//! - Stores all logs in the PostgreSQL database for admin review
//! - Captures user context from tracing spans
//! - Prevents infinite recursion when logging database operations
//!
//! The implementation uses tracing's layered architecture with custom
//! layers for PostgreSQL integration.

use chrono::Utc;
use serde_json::Value as JsonValue;
use sqlx::PgPool;
use std::sync::Arc;
use tracing::{
    Event, Subscriber,
    field::{Field, Visit},
    span::{Attributes, Id, Record},
};
use tracing_bunyan_formatter::{BunyanFormattingLayer, JsonStorageLayer};
use tracing_subscriber::{
    EnvFilter, Registry,
    fmt::{self},
};
use tracing_subscriber::{Layer, prelude::*};
use uuid::Uuid;

use crate::admin::logs::LogEntry;

// Task-local flag to prevent recursive logging when inside a log handler.
// This prevents infinite loops when logging database operations.
tokio::task_local! {
    static IN_LOG_HANDLER: ();
}

/// Custom tracing Layer that captures structured logs and stores them in PostgreSQL.
///
/// This layer:
/// - Captures all events and their fields
/// - Extracts user context from parent spans
/// - Formats the data into a LogEntry structure
/// - Sends the entry to a background task for async database insertion
pub struct PgLogLayer {
    pool: tokio::sync::mpsc::UnboundedSender<LogEntry>,
}

impl<S> Layer<S> for PgLogLayer
where
    S: Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, ctx: tracing_subscriber::layer::Context<'_, S>) {
        // Skip certain modules to prevent infinite recursion and noise
        let target = event.metadata().target();
        if matches!(target, "sqlx::query" | "credor::logging" | "tracing") {
            return;
        }

        let mut visitor = JsonVisitor::default();
        event.record(&mut visitor);

        // Get span fields from the current span, if any
        let mut user_id: Option<String> = None;
        let mut source: Option<String> = None;
        let mut context = serde_json::Map::new();

        if let Some(scope) = ctx.event_scope(event) {
            for span in scope.from_root() {
                let exts = span.extensions();
                if let Some(fields) = exts.get::<JsonVisitor>() {
                    if user_id.is_none() {
                        user_id = fields.user_id.clone();
                    }
                    if source.is_none() {
                        source = fields.source.clone();
                    }
                    context.extend(fields.context.clone());
                }
            }
        }

        // Merge event fields into context
        context.extend(visitor.context.clone());

        let log = LogEntry {
            timestamp: Utc::now(),
            level: event.metadata().level().as_str().to_string(),
            source: source.unwrap_or_else(|| event.metadata().target().to_string()),
            message: visitor.message.unwrap_or_else(|| "No message".into()),
            user_id: user_id.and_then(|s| Uuid::parse_str(s.as_str()).ok()),
            context: Some(JsonValue::Object(context)),
        };

        let _ = self.pool.send(log);
    }

    fn on_new_span(
        &self,
        attrs: &Attributes<'_>,
        id: &Id,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut visitor = JsonVisitor::default();
        attrs.record(&mut visitor);
        if let Some(span) = ctx.span(id) {
            let mut exts = span.extensions_mut();
            exts.insert(visitor);
        }
    }

    fn on_record(
        &self,
        id: &Id,
        values: &Record<'_>,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if let Some(span) = ctx.span(id) {
            let mut exts = span.extensions_mut();
            if let Some(visitor) = exts.get_mut::<JsonVisitor>() {
                values.record(visitor);
            }
        }
    }
}

/// Visitor implementation that collects structured log data from events and spans.
///
/// This visitor extracts:
/// - User ID for tracking which user triggered the log
/// - Source component for categorizing logs
/// - Log message text
/// - Additional context fields as a JSON object
#[derive(Default, Debug)]
struct JsonVisitor {
    user_id: Option<String>,
    source: Option<String>,
    message: Option<String>,
    context: serde_json::Map<String, JsonValue>,
}

impl Visit for JsonVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        match field.name() {
            "user_id" => self.user_id = Some(value.to_string()),
            "source" => self.source = Some(value.to_string()),
            "message" => self.message = Some(value.to_string()),
            k => {
                self.context
                    .insert(k.to_string(), JsonValue::String(value.to_string()));
            }
        }
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let s = format!("{value:?}");
        match field.name() {
            "user_id" => self.user_id = Some(s),
            "source" => self.source = Some(s),
            "message" => self.message = Some(s),
            k => {
                self.context.insert(k.to_string(), JsonValue::String(s));
            }
        }
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.context
            .insert(field.name().to_string(), JsonValue::from(value));
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.context
            .insert(field.name().to_string(), JsonValue::from(value));
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.context
            .insert(field.name().to_string(), JsonValue::from(value));
    }
    fn record_f64(&mut self, field: &Field, value: f64) {
        self.context
            .insert(field.name().to_string(), JsonValue::from(value));
    }
}

/// Initialize the application's structured logging system.
///
/// This function sets up a multi-destination logging pipeline:
/// 1. Structured JSON logs to stdout (using Bunyan format)
/// 2. Pretty-printed logs to stdout for development
/// 3. Structured logs to PostgreSQL for admin review
///
/// # Parameters
/// - `pool`: Connection pool for PostgreSQL database access
///
/// # Example
/// ```rust
/// use std::sync::Arc;
/// use credor::logging::setup_tracing;
///
/// async fn init() {
///     let pool = create_database_pool().await;
///     setup_tracing(Arc::new(pool));
///     // Application is now ready with tracing enabled
/// }
/// ```
pub fn setup_tracing(pool: Arc<PgPool>) {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<LogEntry>();

    // Spawn background task to write logs to database asynchronously
    // This prevents logging operations from blocking request handling
    tokio::spawn(async move {
        while let Some(entry) = rx.recv().await {
            let already_logging = IN_LOG_HANDLER.try_with(|_| ()).is_ok();
            if already_logging {
                continue;
            }

            // Run the DB insert inside the scope
            let _ = IN_LOG_HANDLER
                .scope((), async {
                    let _ = sqlx::query!(
                        r#"
                INSERT INTO system_logs (level, source, message, user_id, context)
                VALUES ($1, $2, $3, $4, $5)
                "#,
                        entry.level,
                        entry.source,
                        entry.message,
                        entry.user_id,
                        entry.context
                    )
                    .execute(&*pool)
                    .await;
                })
                .await;
        }
    });

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,actix_web=info,actix_server=info,mio=info"));

    let bunyan_layer = BunyanFormattingLayer::new(
        "my-app".into(),                                       // Name of the service
        std::io::stdout.with_max_level(tracing::Level::TRACE), // Output
    );

    // Create and initialize the complete tracing subscriber with all layers
    Registry::default()
        .with(env_filter)
        .with(JsonStorageLayer) // Stores span data for bunyan to show full context
        .with(bunyan_layer) // JSON formatted logs to stdout
        .with(fmt::layer().pretty()) // Human-readable logs for development
        .with(PgLogLayer { pool: tx }) // Custom database logger
        .init();
}
