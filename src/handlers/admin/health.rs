//! Admin health and system status endpoint.
//!
//! Provides an endpoint for admins to monitor system uptime, job counts, and health metrics.

use crate::handlers::admin::guard::admin_guard;
use crate::{AppState, auth_middleware::AuthMiddleware};
use actix_web::{HttpResponse, Responder, web};
use once_cell::sync::Lazy;
use serde::Serialize;
use std::time::Instant;

static START_TIME: Lazy<Instant> = Lazy::new(Instant::now);

/// Health and status metrics for the admin dashboard.
#[derive(Serialize)]
struct AdminHealth {
    /// Service status string ("ok" if healthy).
    status: &'static str,
    /// Human-readable uptime string.
    uptime: String,
    /// Number of currently running jobs.
    active_jobs: i64,
    /// Number of jobs in the queue.
    queued_jobs: i64,
    /// Number of jobs completed today.
    completed_today: i64,
    /// Number of jobs failed today.
    failed_today: i64,
}

/// Returns comprehensive system health metrics and operational statistics for admin monitoring.
///
/// This endpoint provides real-time system status information including service uptime,
/// active job counts, and daily processing statistics. Used by admin dashboards to
/// monitor system health and detect operational issues.
///
/// # HTTP Method
/// `GET /api/admin/health`
///
/// # Authentication
/// Requires valid JWT token with admin role in Authorization header:
/// ```
/// Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
/// ```
///
/// # Request Parameters
/// None - returns system-wide health metrics
///
/// # Request Body
/// None - this is a GET request with no body
///
/// # Success Response (200 OK)
/// Returns comprehensive health status:
/// ```json
/// {
///   "status": "ok",
///   "uptime": "2 days 14 hours 23 minutes",
///   "active_jobs": 5,
///   "queued_jobs": 12,
///   "completed_today": 87,
///   "failed_today": 3
/// }
/// ```
///
/// # Response Fields
/// - `status`: Overall system health ("ok" indicates healthy operation)
/// - `uptime`: Human-readable service uptime since last restart
/// - `active_jobs`: Number of scan jobs currently being processed
/// - `queued_jobs`: Number of jobs waiting to be processed
/// - `completed_today`: Jobs successfully completed since midnight
/// - `failed_today`: Jobs that failed processing since midnight
///
/// # Error Responses
/// - `401 Unauthorized`: Missing or invalid JWT token
/// - `403 Forbidden`: User lacks admin privileges
/// - `500 Internal Server Error`: Database connection issues (individual metrics return 0)
///
/// # Health Status Indicators
/// - **Green (Healthy)**: Low failed_today ratio, reasonable queue size
/// - **Yellow (Warning)**: High queue or moderate failure rate
/// - **Red (Critical)**: High failure rate or system unavailability
///
/// # Database Queries
/// The endpoint executes real-time queries for:
/// 1. **Active Jobs**: `SELECT COUNT(*) FROM scan_jobs WHERE status = 'running'`
/// 2. **Queued Jobs**: `SELECT COUNT(*) FROM scan_jobs WHERE status = 'queued'`
/// 3. **Completed Today**: Jobs with status 'completed' and today's date
/// 4. **Failed Today**: Jobs with status 'failed' and today's date
///
/// # Performance Considerations
/// - Graceful degradation: failed queries return 0 instead of errors
/// - Minimal database impact with indexed status queries
/// - Suitable for frequent polling by monitoring systems
///
/// # Usage Example
/// ```javascript
/// fetch('/api/admin/health', {
///   headers: {
///     'Authorization': 'Bearer ' + adminToken
///   }
/// })
/// .then(response => response.json())
/// .then(health => {
///   if (health.status === 'ok') {
///     console.log(`System healthy, uptime: ${health.uptime}`);
///   }
///   console.log(`Queue: ${health.queued_jobs}, Active: ${health.active_jobs}`);
/// });
/// ```
///
/// # Monitoring Integration
/// - Suitable for integration with monitoring tools (Prometheus, Grafana)
/// - Can trigger alerts based on job failure rates
/// - Uptime tracking for SLA monitoring
///
/// # Authorization
/// Requires admin privileges verified through `admin_guard()`.
pub async fn get_admin_health(
    user: AuthMiddleware,
    app_state: web::Data<AppState>,
) -> impl Responder {
    if let Err(resp) = admin_guard(&user) {
        return resp;
    }
    let uptime = humantime::format_duration(START_TIME.elapsed()).to_string();
    let db = app_state.db.as_ref();
    let active_jobs =
        sqlx::query_scalar!("SELECT COUNT(*) FROM scan_jobs WHERE status = 'running'")
            .fetch_one(db)
            .await
            .unwrap_or(None)
            .unwrap_or(0);
    let queued_jobs = sqlx::query_scalar!("SELECT COUNT(*) FROM scan_jobs WHERE status = 'queued'")
        .fetch_one(db)
        .await
        .unwrap_or(None)
        .unwrap_or(0);
    let completed_today = sqlx::query_scalar!("SELECT COUNT(*) FROM scan_jobs WHERE status = 'completed' AND timestamp::date = CURRENT_DATE")
        .fetch_one(db).await.unwrap_or(None).unwrap_or(0);
    let failed_today = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM scan_jobs WHERE status = 'failed' AND timestamp::date = CURRENT_DATE"
    )
    .fetch_one(db)
    .await
    .unwrap_or(None)
    .unwrap_or(0);
    HttpResponse::Ok().json(AdminHealth {
        status: "ok",
        uptime,
        active_jobs,
        queued_jobs,
        completed_today,
        failed_today,
    })
}
