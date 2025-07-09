//! Utility functions for enhanced logging and tracing operations.
//!
//! This module provides helper functions, extractors, and utilities to enhance
//! the logging experience throughout the application. Includes context extraction,
//! performance monitoring, and specialized logging functions.

use actix_web::{HttpMessage, HttpRequest};
use chrono::Utc;
use serde_json::{Value, json};
use std::time::Duration;
use uuid::Uuid;

use crate::auth_middleware::AuthMiddleware;

/// Extract comprehensive request context for logging.
///
/// This function gathers all relevant information from an HTTP request
/// that should be included in log entries for debugging and audit purposes.
pub fn extract_request_context(req: &HttpRequest) -> Value {
    let connection_info = req.connection_info();

    // Extract real IP address considering proxy headers
    let real_ip = extract_real_ip_from_headers(req);

    // Extract user information if available
    let (user_id, user_role, user_email) = req
        .extensions()
        .get::<AuthMiddleware>()
        .map(|auth| (Some(auth.id), Some(auth.role), auth.email.clone()))
        .unwrap_or((None, None, String::new()));

    json!({
        "request": {
            "method": req.method().as_str(),
            "path": req.path(),
            "query_string": req.query_string(),
            "version": format!("{:?}", req.version()),
            "headers": extract_safe_headers(req),
            "remote_addr": connection_info.peer_addr(),
            "real_ip": real_ip,
            "host": req.headers().get("host")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("unknown"),
            "user_agent": req.headers().get("user-agent")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("unknown"),
            "referer": req.headers().get("referer")
                .and_then(|h| h.to_str().ok()),
            "content_type": req.headers().get("content-type")
                .and_then(|h| h.to_str().ok()),
            "content_length": req.headers().get("content-length")
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0),
            "accept": req.headers().get("accept")
                .and_then(|h| h.to_str().ok()),
            "accept_language": req.headers().get("accept-language")
                .and_then(|h| h.to_str().ok()),
            "accept_encoding": req.headers().get("accept-encoding")
                .and_then(|h| h.to_str().ok())
        },
        "user": {
            "id": user_id,
            "role": user_role,
            "email": user_email,
            "authenticated": user_id.is_some()
        },
        "timestamp": Utc::now(),
        "request_id": generate_request_id()
    })
}

/// Extract real IP address from various proxy headers.
fn extract_real_ip_from_headers(req: &HttpRequest) -> String {
    let headers_to_check = [
        "x-forwarded-for",
        "x-real-ip",
        "x-client-ip",
        "cf-connecting-ip",
        "true-client-ip",
        "x-cluster-client-ip",
        "x-forwarded",
        "forwarded-for",
        "forwarded",
    ];

    for header_name in &headers_to_check {
        if let Some(header_value) = req.headers().get(*header_name) {
            if let Ok(ip_str) = header_value.to_str() {
                // Handle comma-separated IPs (take the first one)
                let first_ip = ip_str.split(',').next().unwrap_or("").trim();
                if !first_ip.is_empty() && first_ip != "unknown" && is_valid_ip(first_ip) {
                    return first_ip.to_string();
                }
            }
        }
    }

    // Fallback to connection info
    req.connection_info()
        .peer_addr()
        .unwrap_or("unknown")
        .to_string()
}

/// Extract safe headers for logging (excludes sensitive information).
fn extract_safe_headers(req: &HttpRequest) -> Value {
    let sensitive_headers = [
        "authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "authentication",
        "proxy-authorization",
    ];

    let mut safe_headers = serde_json::Map::new();

    for (name, value) in req.headers() {
        let header_name = name.as_str().to_lowercase();

        if sensitive_headers.contains(&header_name.as_str()) {
            safe_headers.insert(header_name, json!("[REDACTED]"));
        } else if let Ok(header_value) = value.to_str() {
            safe_headers.insert(header_name, json!(header_value));
        }
    }

    json!(safe_headers)
}

/// Simple IP address validation.
fn is_valid_ip(ip: &str) -> bool {
    ip.parse::<std::net::IpAddr>().is_ok()
}

/// Generate a unique request ID for correlation.
pub fn generate_request_id() -> String {
    format!("req_{}", Uuid::new_v4().simple())
}

/// Performance timer for measuring operation durations.
#[derive(Debug)]
pub struct PerformanceTimer {
    start_time: chrono::DateTime<chrono::Utc>,
    pub operation_name: String,
    pub user_id: Option<Uuid>,
}

impl PerformanceTimer {
    /// Start a new performance timer.
    pub fn start(operation_name: &str, user_id: Option<Uuid>) -> Self {
        Self {
            start_time: chrono::Utc::now(),
            operation_name: operation_name.to_string(),
            user_id,
        }
    }

    /// Stop the timer and log the performance metrics.
    pub async fn stop(self) -> chrono::Duration {
        let end_time = chrono::Utc::now();
        let duration = end_time.signed_duration_since(self.start_time);

        // NOTE: You must pass db_writer as the first argument when calling this in real code!
        // crate::tracing::log_performance_metric(
        //     db_writer,
        //     &self.operation_name,
        //     duration.num_milliseconds() as u64,
        //     self.user_id,
        //     Some(json!({
        //         "start_time": self.start_time.to_rfc3339(),
        //         "end_time": end_time.to_rfc3339(),
        //         "duration_ns": duration.num_nanoseconds().unwrap_or(0),
        //         "duration_us": duration.num_microseconds().unwrap_or(0),
        //         "duration_ms": duration.num_milliseconds()
        //     })),
        // )
        // .await;

        duration
    }

    /// Get elapsed time without stopping the timer.
    pub fn elapsed(&self) -> chrono::Duration {
        chrono::Utc::now().signed_duration_since(self.start_time)
    }
}

/// Macro for easy performance timing.
#[macro_export]
macro_rules! time_operation {
    ($operation:expr, $user_id:expr, $code:block) => {{
        let timer = $crate::tracing::utils::PerformanceTimer::start($operation, $user_id);
        let result = $code;
        timer.stop().await;
        result
    }};
    ($operation:expr, $code:block) => {{
        let timer = $crate::tracing::utils::PerformanceTimer::start($operation, None);
        let result = $code;
        timer.stop().await;
        result
    }};
}

/// Extract database operation context for logging.
pub fn create_db_context(
    table: &str,
    operation: &str,
    affected_rows: Option<u64>,
    query_duration: Option<Duration>,
) -> Value {
    json!({
        "database": {
            "table": table,
            "operation": operation,
            "affected_rows": affected_rows,
            "query_duration_ms": query_duration.map(|d| d.as_millis()),
            "timestamp": Utc::now()
        }
    })
}

/// Create authentication event context.
pub fn create_auth_context(
    event_type: &str,
    user_id: Option<Uuid>,
    success: bool,
    details: Option<Value>,
) -> Value {
    json!({
        "authentication": {
            "event_type": event_type,
            "user_id": user_id,
            "success": success,
            "timestamp": Utc::now(),
            "details": details
        }
    })
}

/// Create scan operation context.
pub fn create_scan_context(
    job_id: Uuid,
    user_id: Uuid,
    target_url: &str,
    status: &str,
    confidence: Option<f32>,
    additional_data: Option<Value>,
) -> Value {
    json!({
        "scan_operation": {
            "job_id": job_id,
            "user_id": user_id,
            "target_url": target_url,
            "status": status,
            "confidence": confidence,
            "timestamp": Utc::now(),
            "additional_data": additional_data
        }
    })
}

/// Create error context with stack trace and error details.
pub fn create_error_context(
    error: &dyn std::error::Error,
    operation: &str,
    additional_context: Option<Value>,
) -> Value {
    let mut error_chain = Vec::new();
    let mut current_error: &dyn std::error::Error = error;

    loop {
        error_chain.push(json!({
            "message": current_error.to_string(),
            "type": std::any::type_name_of_val(current_error)
        }));

        match current_error.source() {
            Some(source) => current_error = source,
            None => break,
        }
    }

    json!({
        "error": {
            "operation": operation,
            "error_chain": error_chain,
            "timestamp": Utc::now(),
            "additional_context": additional_context
        }
    })
}

/// Redact sensitive information from JSON values.
pub fn redact_sensitive_data(mut value: Value) -> Value {
    if let Some(obj) = value.as_object_mut() {
        let sensitive_keys = [
            "password",
            "token",
            "secret",
            "key",
            "authorization",
            "cookie",
            "session",
            "refresh_token",
            "access_token",
            "api_key",
            "private_key",
            "client_secret",
            "jwt",
            "bearer",
            "auth",
            "credential",
            "pin",
            "ssn",
            "credit_card",
            "cvv",
            "social_security",
        ];

        for (key, val) in obj.iter_mut() {
            let key_lower = key.to_lowercase();
            if sensitive_keys
                .iter()
                .any(|&sensitive| key_lower.contains(sensitive))
            {
                *val = json!("[REDACTED]");
            } else if val.is_object() || val.is_array() {
                *val = redact_sensitive_data(val.clone());
            }
        }
    } else if let Some(arr) = value.as_array_mut() {
        for item in arr.iter_mut() {
            *item = redact_sensitive_data(item.clone());
        }
    }

    value
}

/// Create a structured log entry for audit trails.
pub fn create_audit_log(
    action: &str,
    resource: &str,
    user_id: Option<Uuid>,
    changes: Option<Value>,
    metadata: Option<Value>,
) -> Value {
    json!({
        "audit": {
            "action": action,
            "resource": resource,
            "user_id": user_id,
            "changes": changes,
            "metadata": metadata,
            "timestamp": Utc::now(),
            "audit_id": Uuid::new_v4()
        }
    })
}

/// Helper to format duration in human-readable format.
pub fn format_duration(duration: Duration) -> String {
    let total_ms = duration.as_millis();

    if total_ms < 1000 {
        format!("{}ms", total_ms)
    } else if total_ms < 60000 {
        format!("{:.2}s", total_ms as f64 / 1000.0)
    } else {
        let minutes = total_ms / 60000;
        let seconds = (total_ms % 60000) as f64 / 1000.0;
        format!("{}m {:.2}s", minutes, seconds)
    }
}

/// Extract correlation ID from request headers or generate a new one.
pub fn get_or_create_correlation_id(req: &HttpRequest) -> String {
    req.headers()
        .get("x-correlation-id")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_owned())
        .unwrap_or_else(|| format!("corr_{}", Uuid::new_v4().simple()))
}

/// Create system health context for monitoring logs.
pub fn create_system_health_context(
    component: &str,
    status: &str,
    metrics: Option<Value>,
) -> Value {
    json!({
        "system_health": {
            "component": component,
            "status": status,
            "metrics": metrics,
            "timestamp": Utc::now(),
            "check_id": Uuid::new_v4()
        }
    })
}

/// Log level utilities.
pub mod log_level {
    /// Determine appropriate log level based on HTTP status code.
    pub fn from_http_status(status_code: u16) -> &'static str {
        match status_code {
            200..=299 => "INFO",
            300..=399 => "INFO",
            400..=499 => "WARN",
            500..=599 => "ERROR",
            _ => "INFO",
        }
    }

    /// Determine log level based on operation duration.
    pub fn from_duration(duration_ms: u64) -> &'static str {
        match duration_ms {
            0..=100 => "DEBUG",
            101..=1000 => "INFO",
            1001..=5000 => "WARN",
            _ => "ERROR",
        }
    }

    /// Check if log level should be elevated based on context.
    pub fn should_elevate(base_level: &str, context: &serde_json::Value) -> String {
        // Elevate to ERROR if security context is present
        if context.get("security").is_some() {
            return "ERROR".to_string();
        }

        // Elevate to WARN if performance issues detected
        if let Some(perf) = context.get("performance") {
            if let Some(duration) = perf.get("duration_ms") {
                if duration.as_u64().unwrap_or(0) > 2000 {
                    return "WARN".to_string();
                }
            }
        }

        base_level.to_string()
    }
}

/// Sampling utilities for high-volume logging.
pub mod sampling {
    use std::sync::atomic::{AtomicU64, Ordering};

    use rand::{Rng, rngs::ThreadRng};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Sample every nth request for high-volume endpoints.
    pub fn should_sample(sample_rate: u64) -> bool {
        if sample_rate == 0 {
            return false;
        }

        let count = COUNTER.fetch_add(1, Ordering::Relaxed);
        count % sample_rate == 0
    }

    /// Sample based on percentage (0.0 to 1.0).
    pub fn should_sample_percentage(percentage: f64) -> bool {
        let mut rng = ThreadRng::default();
        let random_value: f64 = rng.random();
        random_value < percentage
    }
}
