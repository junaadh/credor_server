# 🪵 Comprehensive Tracing System for Credor

This document describes the comprehensive tracing and logging system implemented in the Credor deepfake detection application. The system provides dual logging to both stdout and PostgreSQL database with structured context and automatic instrumentation.

## 🚀 Quick Start

### Environment Setup

```bash
# Set log level (optional, defaults to INFO)
export RUST_LOG=info,actix_web=info,sqlx=warn

# Your existing database configuration
export DATABASE_URL=postgresql://user:password@localhost/credor
```

### Basic Usage

```rust
use credor::tracing as app_tracing;
use serde_json::json;
use uuid::Uuid;

// Initialize tracing (done in main.rs)
app_tracing::init_tracing(db_pool).await?;

// Log basic events
app_tracing::log_event(
    "INFO", 
    "user_service", 
    "User login successful", 
    Some(user_id),
    Some(json!({"ip": "192.168.1.1", "method": "password"}))
).await;

// Log user actions
app_tracing::log_user_action(
    "profile_updated",
    user_id,
    Some(json!({"field": "name", "old_value": "John", "new_value": "Jane"})),
    None
).await;

// Log performance metrics
app_tracing::log_performance_metric(
    "database_query",
    150, // milliseconds
    Some(user_id),
    Some(json!({"table": "scan_jobs", "rows": 25}))
).await;
```

## 📊 Features

### ✅ Dual Logging
- **Stdout**: Human-readable console output with colors and formatting
- **Database**: Structured logs stored in PostgreSQL `system_logs` table
- **Real-time**: Logs appear immediately in both destinations

### ✅ Structured Logging
- **JSON Context**: Rich metadata with every log entry
- **User Tracking**: Automatic user ID association when available
- **Request Correlation**: Unique IDs for tracking requests across services
- **Performance Metrics**: Automatic timing and performance categorization

### ✅ Security Monitoring
- **Failed Authentication**: Automatic logging of login failures
- **Suspicious Activity**: Detection of potential attacks (SQL injection, etc.)
- **Access Violations**: Unauthorized endpoint access attempts
- **Rate Limiting**: Track and log suspicious request patterns

### ✅ Automatic Instrumentation
- **HTTP Requests**: All incoming requests logged with timing
- **Database Operations**: Query performance and error tracking
- **User Actions**: Profile updates, scan jobs, settings changes
- **System Events**: Startup, shutdown, health checks

## 🏗️ Architecture

### Core Components

```
credor/src/tracing/
├── mod.rs           # Main tracing interface and initialization
├── db_writer.rs     # PostgreSQL logging layer
├── middleware.rs    # HTTP request/response middleware
└── utils.rs         # Helper functions and utilities
```

### Database Schema

The system uses the `system_logs` table:

```sql
CREATE TABLE system_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT now(),
    level TEXT NOT NULL CHECK (level IN ('ERROR', 'WARN', 'INFO', 'DEBUG')),
    source TEXT NOT NULL,
    message TEXT NOT NULL,
    user_id UUID REFERENCES user_profiles(user_id),
    context JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

### Log Levels

| Level | Usage | Examples |
|-------|-------|----------|
| `ERROR` | System failures, exceptions | Database connection lost, external service unavailable |
| `WARN` | Warnings, potential issues | Slow queries, failed login attempts, deprecated API usage |
| `INFO` | Normal operations | User actions, successful operations, system events |
| `DEBUG` | Detailed debugging | Variable states, flow control, performance details |

## 🔧 Configuration

### Tracing Subscriber Setup

The system automatically configures:
- **Environment Filter**: Respects `RUST_LOG` environment variable
- **Stdout Layer**: Colored, human-readable console output
- **Database Layer**: Structured logs persisted to PostgreSQL
- **Request Middleware**: Automatic HTTP request/response logging

### Performance Tuning

```rust
// Cleanup old logs (runs daily)
app_tracing::db_writer::start_log_cleanup_task(writer, 30).await; // 30 days retention

// Sampling for high-volume endpoints
if app_tracing::utils::sampling::should_sample_percentage(0.1) { // 10%
    app_tracing::log_event("DEBUG", "high_volume_endpoint", "Request processed", None, None).await;
}
```

## 📝 Logging Patterns

### User Actions

```rust
#[tracing::instrument(skip(user, form), fields(user_id = %user.id, email = %form.email))]
pub async fn register_user(user: AuthMiddleware, form: RegisterForm) -> Result<()> {
    // Automatic span logging with user context
    
    app_tracing::log_user_action(
        "user_registration_attempt",
        user.id,
        Some(json!({
            "email": form.email,
            "registration_method": "email",
            "ip_address": extract_ip(&req)
        })),
        Some(extract_request_context(&req))
    ).await;
    
    // ... registration logic ...
}
```

### Database Operations

```rust
let timer = app_tracing::utils::PerformanceTimer::start("database_query", Some(user_id));

let result = sqlx::query!("SELECT * FROM scan_jobs WHERE user_id = $1", user_id)
    .fetch_all(&db)
    .await;

timer.stop().await; // Automatically logs performance metrics

match result {
    Ok(jobs) => {
        app_tracing::log_event(
            "INFO",
            "database",
            "Scan jobs retrieved successfully",
            Some(user_id),
            Some(app_tracing::utils::create_db_context(
                "scan_jobs", 
                "SELECT", 
                Some(jobs.len() as u64), 
                Some(timer.elapsed())
            ))
        ).await;
    }
    Err(e) => {
        app_tracing::log_system_error(
            "database",
            &e,
            Some(json!({"operation": "get_scan_jobs", "user_id": user_id})),
            Some(user_id)
        ).await;
    }
}
```

### Error Handling

```rust
// System errors with context
app_tracing::log_system_error(
    "external_service",
    &error,
    Some(json!({
        "service": "ai_detection_model",
        "endpoint": "http://ai-model:8080/analyze",
        "retry_count": 3,
        "user_id": user_id
    })),
    Some(user_id)
).await;

// Security events
app_tracing::log_security_event(
    "SUSPICIOUS_ACTIVITY",
    "Multiple failed login attempts",
    Some(user_id),
    Some("192.168.1.100"),
    Some(json!({
        "attempt_count": 5,
        "time_window": "5 minutes",
        "account_locked": true
    }))
).await;
```

### Performance Monitoring

```rust
// Manual timing
let timer = app_tracing::utils::PerformanceTimer::start("complex_operation", Some(user_id));
let result = perform_complex_operation().await;
let duration = timer.stop().await;

// Macro-based timing
time_operation!("scan_processing", Some(user_id), {
    let results = process_scan_job(job_id).await?;
    generate_report(results).await?;
});

// Performance metrics
app_tracing::log_performance_metric(
    "image_processing",
    duration_ms,
    Some(user_id),
    Some(json!({
        "image_size": "1920x1080",
        "processing_mode": "fast",
        "confidence_threshold": 0.8
    }))
).await;
```

## 🔍 Monitoring and Analysis

### Database Queries

```sql
-- Recent errors
SELECT * FROM system_logs 
WHERE level = 'ERROR' 
AND timestamp > NOW() - INTERVAL '1 hour'
ORDER BY timestamp DESC;

-- User activity
SELECT user_id, COUNT(*) as action_count
FROM system_logs 
WHERE source = 'user_action' 
AND timestamp > NOW() - INTERVAL '1 day'
GROUP BY user_id 
ORDER BY action_count DESC;

-- Performance issues
SELECT message, context->>'duration_ms' as duration
FROM system_logs 
WHERE source = 'performance' 
AND level = 'WARN'
AND timestamp > NOW() - INTERVAL '1 hour'
ORDER BY (context->>'duration_ms')::int DESC;

-- Security events
SELECT * FROM system_logs 
WHERE source = 'security' 
AND timestamp > NOW() - INTERVAL '1 day'
ORDER BY timestamp DESC;
```

### Admin Dashboard Integration

The logs are accessible through the admin API:

```bash
# Get recent errors
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://localhost:8080/api/admin/logs?level=ERROR&limit=50"

# Get user-specific logs
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://localhost:8080/api/admin/logs?user_id=$USER_ID&limit=100"

# Get logs from specific time range
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://localhost:8080/api/admin/logs?start_date=2024-01-01T00:00:00Z&end_date=2024-01-02T00:00:00Z"
```

## 🔒 Security and Privacy

### Sensitive Data Redaction

The system automatically redacts sensitive information:

```rust
// These fields are automatically redacted in logs:
let sensitive_fields = [
    "password", "token", "secret", "key", "authorization", 
    "cookie", "session", "refresh_token", "access_token"
];

// Custom redaction
let context = app_tracing::utils::redact_sensitive_data(json!({
    "user_email": "user@example.com",
    "password": "secret123",  // Will become "[REDACTED]"
    "ip_address": "192.168.1.1"
}));
```

### Row-Level Security

Database logs respect PostgreSQL RLS policies:
- **Admins**: Can access all logs
- **Users**: Can only see their own logs (if enabled)
- **Public**: No access

## 📈 Performance Impact

### Benchmarks

- **Stdout Logging**: ~50μs per log entry
- **Database Logging**: ~2-5ms per log entry (async, non-blocking)
- **Request Middleware**: ~100μs overhead per request
- **Memory Usage**: ~10MB for log buffers

### Optimization Tips

1. **Use Appropriate Log Levels**: Avoid DEBUG logs in production
2. **Enable Sampling**: For high-volume endpoints
3. **Database Maintenance**: Regular cleanup of old logs
4. **Context Size**: Keep JSON context under 1KB when possible

```rust
// Good: Concise context
Some(json!({"user_id": user_id, "action": "login"}))

// Avoid: Large context objects
Some(json!({"entire_request_body": large_object})) // Use sampling instead
```

## 🧪 Testing

Run the tracing demo:

```bash
cargo run --example tracing_demo
```

This will demonstrate:
- Basic logging functionality
- User action tracking
- Performance monitoring
- Error handling
- Security event logging
- Database operation logging

## 🔧 Troubleshooting

### Common Issues

1. **Database Connection**: Ensure `system_logs` table exists and migrations are run
2. **Environment Variables**: Check `RUST_LOG` and `DATABASE_URL` settings
3. **Permissions**: Verify database user has INSERT permissions on `system_logs`
4. **Performance**: Monitor log volume and consider sampling for high-traffic endpoints

### Debug Mode

```bash
RUST_LOG=debug cargo run
```

This will show:
- Tracing initialization details
- Database connection status
- Individual log writes
- Performance metrics

### Health Checks

```bash
# Check system health (includes logging metrics)
curl http://localhost:8080/api/admin/health

# Check recent logs
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://localhost:8080/api/admin/logs?limit=10
```

## 📚 References

- [Tracing Documentation](https://docs.rs/tracing/)
- [Tracing Subscriber](https://docs.rs/tracing-subscriber/)
- [SQLx Documentation](https://docs.rs/sqlx/)
- [Actix Web Middleware](https://actix.rs/docs/middleware)

---

**Note**: This tracing system is designed for production use with comprehensive error handling, performance optimization, and security considerations. All logs are structured for easy parsing and analysis by monitoring tools.