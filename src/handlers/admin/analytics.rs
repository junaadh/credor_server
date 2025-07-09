//! Admin analytics endpoint with real-time metrics.
//!
//! Provides real-time analytics metrics for the admin dashboard by querying
//! the database for current user activity, scan job statistics, and confidence scores.

use crate::AppState;
use crate::auth_middleware::AuthMiddleware;
use crate::handlers::admin::guard::admin_guard;
use actix_web::{HttpResponse, Responder, web};
use serde::Serialize;

/// Response payload for admin analytics metrics.
#[derive(Serialize)]
pub struct AdminAnalytics {
    /// Number of users active today.
    pub active_users_today: i64,
    /// Total number of scan jobs submitted.
    pub total_jobs: i64,
    /// Average confidence score across all jobs.
    pub avg_confidence: f32,
}

/// Returns real-time analytics metrics for the admin dashboard.
///
/// This endpoint provides key performance indicators and system statistics by querying
/// the database for current user activity, job processing metrics, and detection model
/// performance data. All metrics are calculated in real-time for up-to-date dashboard displays.
///
/// # HTTP Method
/// `GET /api/admin/analytics`
///
/// # Authentication
/// Requires valid JWT token with admin role in Authorization header:
/// ```
/// Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
/// ```
///
/// # Request Parameters
/// None - returns system-wide analytics
///
/// # Request Body
/// None - this is a GET request with no body
///
/// # Success Response (200 OK)
/// Returns real-time analytics data:
/// ```json
/// {
///   "active_users_today": 42,
///   "total_jobs": 1337,
///   "avg_confidence": 0.847
/// }
/// ```
///
/// # Response Fields
/// - `active_users_today`: Number of unique users who signed in today (based on `last_sign_in_at`)
/// - `total_jobs`: Total count of all scan jobs ever submitted to the system
/// - `avg_confidence`: Average confidence score across all scan results (0.0-1.0 scale)
///
/// # Error Responses
/// - `401 Unauthorized`: Missing or invalid JWT token
/// - `403 Forbidden`: User lacks admin privileges
/// - `500 Internal Server Error`: Database query failures (returns 0 for failed metrics)
///
/// # Database Queries
/// The endpoint executes three main queries:
/// 1. **Active Users**: Joins `user_profiles` with `auth.users` to count daily logins
/// 2. **Total Jobs**: Simple count from `scan_jobs` table
/// 3. **Average Confidence**: Calculates mean of all non-null confidence scores
///
/// # Performance Notes
/// - Queries are optimized for real-time dashboard updates
/// - Failed queries gracefully return 0 instead of errors
/// - Consider caching for high-traffic admin dashboards
///
/// # Usage Example
/// ```javascript
/// fetch('/api/admin/analytics', {
///   headers: {
///     'Authorization': 'Bearer ' + adminToken
///   }
/// })
/// .then(response => response.json())
/// .then(data => {
///   console.log(`${data.active_users_today} users active today`);
///   console.log(`${data.total_jobs} total jobs processed`);
///   console.log(`Average confidence: ${data.avg_confidence}`);
/// });
/// ```
///
/// # Authorization
/// Requires admin privileges verified through `admin_guard()`.
///
/// # Database Impact
/// - Read-only operations with minimal performance impact
/// - Uses COUNT() and AVG() aggregations
/// - Filters by date for active user calculation
/// Returns real-time analytics metrics for the admin dashboard.
/// Adds tracing instrumentation and logs key events and errors with structured fields.
#[tracing::instrument(skip(user, app_state), fields(admin_id = %user.id))]
pub async fn get_admin_analytics(
    user: AuthMiddleware,
    app_state: web::Data<AppState>,
) -> impl Responder {
    if let Err(resp) = admin_guard(&user) {
        tracing::warn!(
            admin_id = %user.id,
            "Admin analytics access denied (not an admin)"
        );
        return resp;
    }

    // Query for active users today (users who signed in today)
    let active_users_today = sqlx::query_scalar!(
        r#"
        SELECT COUNT(DISTINCT user_id)
        FROM user_profiles
        WHERE user_id IN (
            SELECT id
            FROM auth.users
            WHERE last_sign_in_at::date = CURRENT_DATE
        )
        "#
    )
    .fetch_one(app_state.db.as_ref())
    .await
    .unwrap_or(Some(0))
    .unwrap_or(0);

    // Query for total scan jobs
    let total_jobs = sqlx::query_scalar!("SELECT COUNT(*) FROM scan_jobs")
        .fetch_one(app_state.db.as_ref())
        .await
        .unwrap_or(Some(0))
        .unwrap_or(0);

    // Query for average confidence score
    let avg_confidence = sqlx::query_scalar!(
        "SELECT AVG(confidence) FROM scan_results WHERE confidence IS NOT NULL"
    )
    .fetch_one(app_state.db.as_ref())
    .await
    .unwrap_or(Some(0.0))
    .unwrap_or(0.0) as f32;

    tracing::info!(
        admin_id = %user.id,
        active_users_today,
        total_jobs,
        avg_confidence,
        "Admin analytics metrics retrieved successfully"
    );

    HttpResponse::Ok().json(AdminAnalytics {
        active_users_today,
        total_jobs,
        avg_confidence,
    })
}
