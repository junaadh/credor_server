//! Admin scan job management endpoints.
//!
//! Provides handlers for listing, retrieving, updating, and deleting scan jobs and their results
//! for admin moderation. All endpoints use structured tracing for observability.

use crate::handlers::admin::guard::admin_guard;
use crate::{AppState, auth_middleware::AuthMiddleware};
use actix_web::{HttpResponse, Responder, web};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Summary information for a scan job as seen by an admin.
#[derive(Serialize)]
pub struct AdminScanJobSummary {
    /// The scan job's unique identifier.
    pub job_id: Uuid,
    /// The user who submitted the scan job.
    pub user_id: Uuid,
    /// The scan target (e.g., keyword or URL).
    pub target: String,
    /// The current status of the scan job.
    pub status: Option<String>,
    /// The timestamp when the job was created.
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// The number of results associated with this job.
    pub result_count: i64,
}

/// Query parameters for pagination.
#[derive(Deserialize)]
pub struct Pagination {
    /// Maximum number of items to return.
    pub limit: i64,
    /// Number of items to skip.
    pub offset: i64,
}

/// Retrieves a paginated list of all scan jobs in the system for admin review and moderation.
///
/// This endpoint provides administrators with a comprehensive view of all scan jobs
/// submitted by users, including job metadata, processing status, and result counts.
/// Supports pagination for efficient browsing of large job datasets.
///
/// # HTTP Method
/// `GET /api/admin/scans`
///
/// # Authentication
/// Requires valid JWT token with admin role in Authorization header:
/// ```
/// Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
/// ```
///
/// # Query Parameters
/// - `limit`: Maximum number of jobs to return (required)
/// - `offset`: Number of jobs to skip for pagination (required)
///
/// # Request Examples
/// ```
/// GET /api/admin/scans?limit=50&offset=0
/// GET /api/admin/scans?limit=25&offset=100
/// ```
///
/// # Success Response (200 OK)
/// Returns an array of scan job summaries:
/// ```json
/// [
///   {
///     "job_id": "550e8400-e29b-41d4-a716-446655440000",
///     "user_id": "123e4567-e89b-12d3-a456-426614174000",
///     "target": "https://example.com/video.mp4",
///     "status": "completed",
///     "timestamp": "2024-01-15T10:30:00Z",
///     "result_count": 3
///   },
///   {
///     "job_id": "660f9500-f39c-52e5-b827-557766551111",
///     "user_id": "234f5678-f89c-23e4-b567-537725285111",
///     "target": "https://example.com/image.jpg",
///     "status": "pending",
///     "timestamp": "2024-01-15T09:45:00Z",
///     "result_count": 0
///   }
/// ]
/// ```
///
/// # Error Responses
/// - `401 Unauthorized`: Missing or invalid JWT token
/// - `403 Forbidden`: User lacks admin privileges
/// - `500 Internal Server Error`: Database query failures
///
/// # Pagination
/// Use limit and offset for paginating through scan jobs:
/// - Results are ordered by timestamp (newest first)
/// - Typical page sizes: 25, 50, or 100 jobs
/// - Calculate total pages using result_count from individual queries
///
/// # Authorization
/// Requires admin privileges verified through `admin_guard()`.
/// Retrieves a paginated list of all scan jobs in the system for admin review.
/// Adds tracing instrumentation and logs key events and errors with structured fields.
#[tracing::instrument(skip(user, app_state, pagination), fields(admin_id = %user.id))]
pub async fn get_scans(
    user: AuthMiddleware,
    app_state: web::Data<AppState>,
    web::Query(pagination): web::Query<Pagination>,
) -> impl Responder {
    if let Err(resp) = admin_guard(&user) {
        tracing::warn!(
            admin_id = %user.id,
            "Admin scan list access denied (not an admin)"
        );
        return resp;
    }
    let rows = sqlx::query!(
        r#"SELECT job_id, user_id, target, status, timestamp,
            (SELECT COUNT(*) FROM scan_results WHERE scan_results.job_id = scan_jobs.job_id) as result_count
           FROM scan_jobs
           ORDER BY timestamp DESC
           LIMIT $1 OFFSET $2"#,
        pagination.limit,
        pagination.offset
    )
    .fetch_all(app_state.db.as_ref())
    .await;
    match rows {
        Ok(scans) => {
            let mapped: Vec<AdminScanJobSummary> = scans
                .into_iter()
                .map(|s| AdminScanJobSummary {
                    job_id: s.job_id,
                    user_id: s.user_id,
                    target: s.target,
                    status: s.status,
                    timestamp: s.timestamp.unwrap_or_else(chrono::Utc::now),
                    result_count: s.result_count.unwrap_or(0),
                })
                .collect();

            tracing::info!(
                admin_id = %user.id,
                scan_count = mapped.len(),
                limit = pagination.limit,
                offset = pagination.offset,
                "Admin retrieved scan job list"
            );

            HttpResponse::Ok().json(mapped)
        }
        Err(e) => {
            tracing::error!(
                admin_id = %user.id,
                error = ?e,
                "Failed to fetch scan jobs for admin"
            );

            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "Failed to fetch scans"}))
        }
    }
}

/// Detailed information for a scan job as seen by an admin.
#[derive(Serialize)]
pub struct AdminScanJobDetail {
    /// The scan job's unique identifier.
    pub job_id: Uuid,
    /// The user who submitted the scan job.
    pub user_id: Uuid,
    /// The scan target (e.g., keyword or URL).
    pub target: String,
    /// The current status of the scan job.
    pub status: Option<String>,
    /// The timestamp when the job was created.
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Optional notes for the scan job.
    pub notes: Option<String>,
    /// Optional priority for the scan job.
    pub priority: Option<String>,
}

/// Represents a scan result as seen by an admin.
#[derive(Serialize)]
pub struct AdminScanResult {
    /// The result's unique identifier.
    pub result_id: Uuid,
    /// The associated scan job's ID.
    pub job_id: Uuid,
    /// The media URL analyzed.
    pub media_url: Option<String>,
    /// The confidence score from the detection model.
    pub confidence: Option<f32>,
    /// The label assigned by the detection model.
    pub label: Option<String>,
    /// The timestamp when the result was detected.
    pub detected_at: chrono::DateTime<chrono::Utc>,
}

/// Retrieves comprehensive details and all results for a specific scan job.
///
/// This endpoint provides administrators with complete information about a scan job,
/// including job metadata, processing details, and all associated detection results.
/// Used for detailed job inspection, debugging, and result moderation.
///
/// # HTTP Method
/// `GET /api/admin/scans/{job_id}`
///
/// # Authentication
/// Requires valid JWT token with admin role in Authorization header:
/// ```
/// Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
/// ```
///
/// # Path Parameters
/// - `job_id`: UUID of the scan job to retrieve
///
/// # Success Response (200 OK)
/// Returns detailed job information with all results:
/// ```json
/// {
///   "job": {
///     "job_id": "550e8400-e29b-41d4-a716-446655440000",
///     "user_id": "123e4567-e89b-12d3-a456-426614174000",
///     "target": "https://example.com/video.mp4",
///     "status": "completed",
///     "timestamp": "2024-01-15T10:30:00Z",
///     "notes": "High priority scan",
///     "priority": "high"
///   },
///   "results": [
///     {
///       "result_id": "770f9500-f39c-52e5-b827-557766552222",
///       "job_id": "550e8400-e29b-41d4-a716-446655440000",
///       "media_url": "https://example.com/frame1.jpg",
///       "confidence": 0.89,
///       "label": "FAKE",
///       "detected_at": "2024-01-15T10:32:15Z"
///     },
///     {
///       "result_id": "880f9500-f39c-52e5-b827-557766553333",
///       "job_id": "550e8400-e29b-41d4-a716-446655440000",
///       "media_url": "https://example.com/frame2.jpg",
///       "confidence": 0.23,
///       "label": "REAL",
///       "detected_at": "2024-01-15T10:32:20Z"
///     }
///   ]
/// }
/// ```
///
/// # Error Responses
/// - `401 Unauthorized`: Missing or invalid JWT token
/// - `403 Forbidden`: User lacks admin privileges
/// - `404 Not Found`: Scan job with specified ID does not exist
/// - `500 Internal Server Error`: Database query failures
///
/// # Use Cases
/// - Detailed job inspection and debugging
/// - Result moderation and quality control
/// - Performance analysis and model evaluation
/// - User support and issue resolution
///
/// # Authorization
/// Requires admin privileges verified through `admin_guard()`.
/// Retrieves comprehensive details and all results for a specific scan job.
/// Adds tracing instrumentation and logs key events and errors with structured fields.
#[tracing::instrument(skip(user, app_state), fields(admin_id = %user.id, job_id = %path))]
pub async fn get_scan_details(
    user: AuthMiddleware,
    path: web::Path<Uuid>,
    app_state: web::Data<AppState>,
) -> impl Responder {
    if let Err(resp) = admin_guard(&user) {
        tracing::warn!(
            admin_id = %user.id,
            job_id = %path,
            "Admin scan details access denied (not an admin)"
        );
        return resp;
    }
    let job_id = path.into_inner();
    let job = sqlx::query!(
        r#"SELECT job_id, user_id, target, status, timestamp, notes, priority FROM scan_jobs WHERE job_id = $1"#,
        job_id
    )
    .fetch_optional(app_state.db.as_ref())
    .await;
    match job {
        Ok(Some(job)) => {
            let job_detail = AdminScanJobDetail {
                job_id: job.job_id,
                user_id: job.user_id,
                target: job.target,
                status: job.status,
                timestamp: job.timestamp.unwrap_or_else(chrono::Utc::now),
                notes: job.notes,
                priority: job.priority,
            };
            let results = sqlx::query!(
                r#"SELECT result_id, job_id, media_url, confidence, label, detected_at FROM scan_results WHERE job_id = $1 ORDER BY detected_at DESC"#,
                job_id
            )
            .fetch_all(app_state.db.as_ref())
            .await;
            match results {
                Ok(results) => {
                    let mapped: Vec<AdminScanResult> = results
                        .into_iter()
                        .map(|r| AdminScanResult {
                            result_id: r.result_id,
                            job_id: r.job_id.expect("job_id must exist"),
                            media_url: r.media_url,
                            confidence: r.confidence.map(|v| v as f32),
                            label: r.label,
                            detected_at: r.detected_at.unwrap_or_else(chrono::Utc::now),
                        })
                        .collect();
                    tracing::info!(
                        admin_id = %user.id,
                        job_id = %job_id,
                        result_count = mapped.len(),
                        "Admin retrieved scan job details and results"
                    );

                    HttpResponse::Ok()
                        .json(serde_json::json!({"job": job_detail, "results": mapped}))
                }
                Err(e) => {
                    tracing::error!(
                        admin_id = %user.id,
                        job_id = %job_id,
                        error = ?e,
                        "Failed to fetch scan results for admin"
                    );

                    HttpResponse::InternalServerError()
                        .json(serde_json::json!({"error": "Failed to fetch results"}))
                }
            }
        }
        Ok(None) => {
            tracing::warn!(
                admin_id = %user.id,
                job_id = %job_id,
                "Scan job not found for admin details request"
            );

            HttpResponse::NotFound().json(serde_json::json!({"error": "Scan job not found"}))
        }
        Err(e) => {
            tracing::error!(
                admin_id = %user.id,
                job_id = %job_id,
                error = ?e,
                "Database error when fetching scan job details"
            );

            HttpResponse::InternalServerError().json(serde_json::json!({"error": "DB error"}))
        }
    }
}

/// Request payload for updating scan job status.
#[derive(Deserialize)]
pub struct StatusPatch {
    /// The new status value for the scan job.
    pub status: String,
}

/// Response payload for updated scan job status.
#[derive(Serialize)]
pub struct AdminScanStatus {
    /// The scan job's unique identifier.
    pub job_id: Uuid,
    /// The updated status value.
    pub status: String,
}

/// Updates the processing status of a specific scan job for admin moderation.
///
/// This endpoint allows administrators to manually change scan job status for
/// workflow management, error recovery, and quality control purposes. Status
/// changes affect job processing pipeline and user visibility.
///
/// # HTTP Method
/// `PATCH /api/admin/scans/{job_id}/status`
///
/// # Authentication
/// Requires valid JWT token with admin role in Authorization header:
/// ```
/// Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
/// ```
///
/// # Path Parameters
/// - `job_id`: UUID of the scan job to update
///
/// # Request Body (JSON)
/// ```json
/// {
///   "status": "completed"
/// }
/// ```
///
/// # Valid Status Values
/// - `"queued"`: Job waiting to be processed
/// - `"running"`: Currently being analyzed
/// - `"completed"`: Processing finished successfully
/// - `"failed"`: Processing encountered an error
/// - `"flagged"`: Marked for manual review
///
/// # Success Response (200 OK)
/// Returns the updated job status:
/// ```json
/// {
///   "job_id": "550e8400-e29b-41d4-a716-446655440000",
///   "status": "completed"
/// }
/// ```
///
/// # Error Responses
/// - `400 Bad Request`: Invalid status value (not in allowed list)
/// - `401 Unauthorized`: Missing or invalid JWT token
/// - `403 Forbidden`: User lacks admin privileges
/// - `404 Not Found`: Scan job with specified ID does not exist
/// - `500 Internal Server Error`: Database update failures
///
/// # Admin Use Cases
/// - Retry failed jobs by changing status from "failed" to "queued"
/// - Mark suspicious content as "flagged" for manual review
/// - Force completion of stuck jobs
/// - Reset job status for reprocessing
///
/// # Side Effects
/// - Status changes may trigger background processing
/// - Users see updated status in their job history
/// - Job timeline and audit trail are updated
///
/// # Authorization
/// Requires admin privileges verified through `admin_guard()`.
/// Updates the processing status of a specific scan job for admin moderation.
/// Adds tracing instrumentation and logs key events and errors with structured fields.
#[tracing::instrument(skip(user, app_state, body), fields(admin_id = %user.id, job_id = %path, new_status = %body.status))]
pub async fn patch_scan_status(
    user: AuthMiddleware,
    path: web::Path<Uuid>,
    app_state: web::Data<AppState>,
    web::Json(body): web::Json<StatusPatch>,
) -> impl Responder {
    if let Err(resp) = admin_guard(&user) {
        tracing::warn!(
            admin_id = %user.id,
            job_id = %path,
            "Admin scan status update denied (not an admin)"
        );
        return resp;
    }
    let allowed = ["queued", "running", "completed", "failed", "flagged"];
    if !allowed.contains(&body.status.as_str()) {
        tracing::warn!(
            admin_id = %user.id,
            job_id = %path,
            status = %body.status,
            "Invalid scan status value provided"
        );
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "Invalid status value"}));
    }
    let job_id = path.into_inner();
    let res = sqlx::query!(
        r#"UPDATE scan_jobs SET status = $1 WHERE job_id = $2 RETURNING job_id, status"#,
        body.status,
        job_id
    )
    .fetch_optional(app_state.db.as_ref())
    .await;
    match res {
        Ok(Some(row)) => {
            tracing::info!(
                admin_id = %user.id,
                job_id = %job_id,
                old_status = ?row.status,
                new_status = %body.status,
                "Admin updated scan job status"
            );

            HttpResponse::Ok().json(AdminScanStatus {
                job_id: row.job_id,
                status: row.status.unwrap_or_default(),
            })
        }
        Ok(None) => {
            tracing::warn!(
                admin_id = %user.id,
                job_id = %job_id,
                "Scan job not found for status update"
            );

            HttpResponse::NotFound().json(serde_json::json!({"error": "Scan job not found"}))
        }
        Err(e) => {
            tracing::error!(
                admin_id = %user.id,
                job_id = %job_id,
                status = %body.status,
                error = ?e,
                "Failed to update scan job status"
            );

            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "Failed to update status"}))
        }
    }
}

/// Response payload for deleted scan job.
#[derive(Serialize)]
pub struct AdminScanDelete {
    /// The scan job's unique identifier.
    pub job_id: Uuid,
}

/// Permanently deletes a scan job and all associated detection results.
///
/// This endpoint removes a scan job and its results from the system entirely.
/// Used for data cleanup, privacy compliance, or removing inappropriate content.
/// This operation cannot be undone.
///
/// # HTTP Method
/// `DELETE /api/admin/scans/{job_id}`
///
/// # Authentication
/// Requires valid JWT token with admin role in Authorization header:
/// ```
/// Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
/// ```
///
/// # Path Parameters
/// - `job_id`: UUID of the scan job to delete
///
/// # Success Response (200 OK)
/// Returns confirmation of deletion:
/// ```json
/// {
///   "job_id": "550e8400-e29b-41d4-a716-446655440000"
/// }
/// ```
///
/// # Error Responses
/// - `401 Unauthorized`: Missing or invalid JWT token
/// - `403 Forbidden`: User lacks admin privileges
/// - `404 Not Found`: Scan job with specified ID does not exist
/// - `500 Internal Server Error`: Database deletion failures
///
/// # Deletion Process
/// 1. First deletes all scan results associated with the job
/// 2. Then deletes the scan job record itself
/// 3. Uses database transactions for consistency
/// 4. Gracefully handles missing results (idempotent operation)
///
/// # Admin Use Cases
/// - Remove inappropriate or illegal content
/// - Data privacy compliance (GDPR deletion requests)
/// - System cleanup and storage management
/// - Removing test or duplicate jobs
///
/// # Security Notes
/// - This operation is **irreversible**
/// - All detection results are permanently lost
/// - Consider backup procedures for audit trails
/// - Log all deletion activities for compliance
///
/// # Side Effects
/// - Job disappears from user's scan history
/// - All associated results are permanently removed
/// - Database storage is freed
/// - User cannot access job or results anymore
///
/// # Authorization
/// Requires admin privileges verified through `admin_guard()`.
/// Permanently deletes a scan job and all associated detection results.
/// Adds tracing instrumentation and logs key events and errors with structured fields.
#[tracing::instrument(skip(user, app_state), fields(admin_id = %user.id, job_id = %path))]
pub async fn delete_scan(
    user: AuthMiddleware,
    path: web::Path<Uuid>,
    app_state: web::Data<AppState>,
) -> impl Responder {
    if let Err(resp) = admin_guard(&user) {
        tracing::warn!(
            admin_id = %user.id,
            job_id = %path,
            "Admin scan deletion denied (not an admin)"
        );
        return resp;
    }
    let job_id = path.into_inner();
    let _ = sqlx::query!("DELETE FROM scan_results WHERE job_id = $1", job_id)
        .execute(app_state.db.as_ref())
        .await;
    let res = sqlx::query!(
        "DELETE FROM scan_jobs WHERE job_id = $1 RETURNING job_id",
        job_id
    )
    .fetch_optional(app_state.db.as_ref())
    .await;
    match res {
        Ok(Some(row)) => {
            tracing::info!(
                admin_id = %user.id,
                job_id = %job_id,
                "Admin successfully deleted scan job and results"
            );

            HttpResponse::Ok().json(AdminScanDelete { job_id: row.job_id })
        }
        Ok(None) => {
            tracing::warn!(
                admin_id = %user.id,
                job_id = %job_id,
                "Scan job not found for deletion"
            );

            HttpResponse::NotFound().json(serde_json::json!({"error": "Scan job not found"}))
        }
        Err(e) => {
            tracing::error!(
                admin_id = %user.id,
                job_id = %job_id,
                error = ?e,
                "Failed to delete scan job"
            );

            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "Failed to delete scan job"}))
        }
    }
}
