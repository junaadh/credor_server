//! User scan job and result endpoints.
//!
//! This module provides handlers for creating scan jobs, listing history,
//! and fetching scan results for authenticated users. All endpoints require JWT auth.

use crate::{AppState, auth_middleware::AuthMiddleware};
use actix_web::{HttpRequest, HttpResponse, Responder, web};
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

/// Represents a scan job created by a user.
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct ScanJob {
    /// Unique scan job ID
    pub job_id: Uuid,
    /// User who created the job
    pub user_id: Uuid,
    /// Target URL or keyword for the scan
    pub target_url: String,
    /// Current status (pending, running, completed, failed, etc.)
    pub status: String,
    /// When the job was created
    pub created_at: NaiveDateTime,
}

/// Represents a single scan result for a media item.
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct ScanResult {
    /// Unique result ID
    pub result_id: Uuid,
    /// Associated scan job
    pub job_id: Uuid,
    /// Deepfake confidence score (0.0-1.0)
    pub confidence: f32,
    /// Model label (e.g., "REAL", "FAKE")
    pub label: String,
    /// When the result was created
    pub created_at: NaiveDateTime,
}

/// Creates a new deepfake detection scan job for the authenticated user.
///
/// This endpoint initiates a new scan operation by creating a job record in the database
/// and optionally triggering the background scanning pipeline. The job starts in "pending"
/// status and will be processed by the detection system.
///
/// # HTTP Method
/// `POST /api/user/scan`
///
/// # Authentication
/// Requires valid JWT token in Authorization header:
/// ```
/// Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
/// ```
///
/// # Request Body (JSON)
/// ```json
/// {
///   "target_url": "https://example.com/media/video.mp4"  // String, HTTP/HTTPS URL to media
/// }
/// ```
///
/// # Validation Rules
/// - `target_url`: Must be a valid HTTP or HTTPS URL
/// - URL must start with "http" (http:// or https://)
/// - Required field - cannot be null or empty
///
/// # Success Response (200 OK)
/// Returns the created scan job with initial status:
/// ```json
/// {
///   "job_id": "550e8400-e29b-41d4-a716-446655440000",
///   "user_id": "123e4567-e89b-12d3-a456-426614174000",
///   "target_url": "https://example.com/media/video.mp4",
///   "status": "pending",
///   "created_at": "2024-01-15T10:30:00"
/// }
/// ```
///
/// # Error Responses
/// - `400 Bad Request`: Invalid or missing target_url (non-HTTP URL, empty field)
/// - `401 Unauthorized`: Missing or invalid JWT token
/// - `500 Internal Server Error`: Database errors or job creation failure
///
/// # Job Status Flow
/// 1. **pending**: Job created, waiting to be processed
/// 2. **running**: Currently being analyzed by detection model
/// 3. **completed**: Analysis finished, results available
/// 4. **failed**: Processing error occurred
///
/// # Side Effects
/// - Creates new record in `scan_jobs` table
/// - May trigger background processing pipeline
/// - Job becomes available in user's scan history
/// - User can monitor progress via status endpoint
///
/// # Usage Example
/// ```javascript
/// fetch('/api/user/scan', {
///   method: 'POST',
///   headers: {
///     'Content-Type': 'application/json',
///     'Authorization': 'Bearer ' + userToken
///   },
///   body: JSON.stringify({
///     target_url: 'https://example.com/suspicious-video.mp4'
///   })
/// });
/// ```
#[tracing::instrument(skip(user, app_state, payload, req), fields(user_id = %user.id))]
pub async fn post_scan(
    user: AuthMiddleware,
    app_state: web::Data<AppState>,
    payload: web::Json<serde_json::Value>, // expects {"target_url": ...}
    req: HttpRequest,
) -> impl Responder {
    let db = app_state.db.clone();
    let target_url = match payload.get("target_url").and_then(|v| v.as_str()) {
        Some(url) if url.starts_with("http") => url,
        _ => {
            crate::tracing::log_event(
                db.clone(),
                "WARN",
                "user_scan",
                "Invalid target URL provided for scan",
                Some(user.id),
                Some(json!({
                    "user_id": user.id,
                    "provided_payload": payload.0,
                    "request_context": crate::tracing::utils::extract_request_context(&req)
                })),
            )
            .await;

            return HttpResponse::BadRequest()
                .json(serde_json::json!({"error": "Invalid or missing target_url"}));
        }
    };
    tracing::info!(
        user.id = %user.id,
        target_url = %target_url,
        "Creating new scan job"
    );

    let row = sqlx::query_as::<_, ScanJob>(
        r#"INSERT INTO scan_jobs (user_id, target_url, status) VALUES ($1, $2, 'pending') RETURNING job_id, user_id, target_url, status, created_at"#,
        )
        .bind(user.id)
        .bind(target_url)
        .fetch_one(db.as_ref())
        .await;

    match row {
        Ok(job) => {
            crate::tracing::log_user_action(
                db.clone(),
                "scan_job_created",
                user.id,
                Some(json!({
                    "job_id": job.job_id,
                    "target_url": target_url,
                    "status": "pending"
                })),
                Some(crate::tracing::utils::extract_request_context(&req)),
            )
            .await;

            tracing::info!(
                user.id = %user.id,
                job.id = %job.job_id,
                target_url = %target_url,
                "Scan job created successfully"
            );
            HttpResponse::Ok().json(&job)
        }
        Err(e) => {
            crate::tracing::log_event(
                db.clone(),
                "ERROR",
                "user_scan",
                "Failed to create scan job",
                Some(user.id),
                Some(json!({
                    "user_id": user.id,
                    "target_url": target_url,
                    "error": e.to_string(),
                    "request_context": crate::tracing::utils::extract_request_context(&req)
                })),
            )
            .await;

            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "Failed to create scan job"}))
        }
    }
}

/// Retrieves the scan job history for the authenticated user.
///
/// This endpoint returns a chronologically ordered list of all scan jobs submitted
/// by the user, providing an overview of their scanning activity and job statuses.
///
/// # HTTP Method
/// `GET /api/user/scan/history`
///
/// # Authentication
/// Requires valid JWT token in Authorization header:
/// ```
/// Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
/// ```
///
/// # Request Parameters
/// None - returns all jobs for the authenticated user
///
/// # Request Body
/// None - this is a GET request with no body
///
/// # Success Response (200 OK)
/// Returns an array of scan jobs ordered by creation date (newest first):
/// ```json
/// [
///   {
///     "job_id": "550e8400-e29b-41d4-a716-446655440000",
///     "user_id": "123e4567-e89b-12d3-a456-426614174000",
///     "target_url": "https://example.com/video1.mp4",
///     "status": "completed",
///     "created_at": "2024-01-15T10:30:00"
///   },
///   {
///     "job_id": "660f9500-f39c-52e5-b827-557766551111",
///     "user_id": "123e4567-e89b-12d3-a456-426614174000",
///     "target_url": "https://example.com/video2.mp4",
///     "status": "pending",
///     "created_at": "2024-01-15T09:15:00"
///   }
/// ]
/// ```
///
/// # Error Responses
/// - `401 Unauthorized`: Missing or invalid JWT token
/// - `500 Internal Server Error`: Database query errors
///
/// # Response Limits
/// - Returns up to 50 most recent jobs
/// - Jobs are ordered by creation date (newest first)
/// - Includes jobs in all statuses (pending, running, completed, failed)
///
/// # Usage Example
/// ```javascript
/// fetch('/api/user/scan/history', {
///   headers: {
///     'Authorization': 'Bearer ' + userToken
///   }
/// })
/// .then(response => response.json())
/// .then(jobs => {
///   console.log(`User has ${jobs.length} scan jobs`);
/// });
/// ```
#[tracing::instrument(skip(user, app_state), fields(user_id = %user.id))]
pub async fn get_history(user: AuthMiddleware, app_state: web::Data<AppState>) -> impl Responder {
    tracing::debug!(
        user.id = %user.id,
        "Fetching scan history"
    );

    let rows = sqlx::query_as::<_, ScanJob>(
        r#"SELECT job_id, user_id, target_url, status, created_at FROM scan_jobs WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50"#,
    )
    .bind(user.id)
    .fetch_all(app_state.db.as_ref())
    .await;
    match rows {
        Ok(jobs) => {
            crate::tracing::log_event(
                app_state.db.clone(),
                "INFO",
                "user_scan",
                "Scan history retrieved",
                Some(user.id),
                Some(json!({
                    "user_id": user.id,
                    "job_count": jobs.len(),
                    "operation": "get_history"
                })),
            )
            .await;

            tracing::info!(
                user.id = %user.id,
                job_count = jobs.len(),
                "Scan history retrieved successfully"
            );

            HttpResponse::Ok().json(jobs)
        }
        Err(e) => {
            crate::tracing::log_system_error(
                app_state.db.clone(),
                "user_scan",
                &e,
                Some(json!({
                    "operation": "get_history",
                    "user_id": user.id,
                    "table": "scan_jobs"
                })),
                Some(user.id),
            )
            .await;

            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "Failed to fetch history"}))
        }
    }
}

/// Retrieves the detailed scan results for a specific job owned by the authenticated user.
///
/// This endpoint returns the deepfake detection results including confidence scores,
/// labels, and analysis details for a completed scan job. Users can only access
/// results for their own jobs.
///
/// # HTTP Method
/// `GET /api/user/scan/{job_id}/results`
///
/// # Authentication
/// Requires valid JWT token in Authorization header:
/// ```
/// Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
/// ```
///
/// # Path Parameters
/// - `job_id`: UUID of the scan job (e.g., `550e8400-e29b-41d4-a716-446655440000`)
///
/// # Request Body
/// None - this is a GET request with no body
///
/// # Success Response (200 OK)
/// Returns an array of scan results for the job:
/// ```json
/// [
///   {
///     "result_id": "770f9500-f39c-52e5-b827-557766551111",
///     "job_id": "550e8400-e29b-41d4-a716-446655440000",
///     "confidence": 0.85,
///     "label": "FAKE",
///     "created_at": "2024-01-15T10:32:15"
///   },
///   {
///     "result_id": "880f9500-f39c-52e5-b827-557766552222",
///     "job_id": "550e8400-e29b-41d4-a716-446655440000",
///     "confidence": 0.23,
///     "label": "REAL",
///     "created_at": "2024-01-15T10:32:20"
///   }
/// ]
/// ```
///
/// # Error Responses
/// - `401 Unauthorized`: Missing or invalid JWT token
/// - `404 Not Found`: Job doesn't exist or user doesn't own the job
/// - `500 Internal Server Error`: Database query errors
///
/// # Result Fields
/// - `result_id`: Unique identifier for this specific result
/// - `job_id`: The scan job this result belongs to
/// - `confidence`: Float 0.0-1.0 indicating model confidence in the prediction
/// - `label`: Classification result ("REAL", "FAKE", or other model-specific labels)
/// - `created_at`: Timestamp when this result was generated
///
/// # Authorization
/// - Users can only access results for jobs they own
/// - Job ownership is verified by matching user_id from JWT token
/// - Attempting to access another user's results returns 404
///
/// # Usage Example
/// ```javascript
/// const jobId = '550e8400-e29b-41d4-a716-446655440000';
/// fetch(`/api/user/scan/${jobId}/results`, {
///   headers: {
///     'Authorization': 'Bearer ' + userToken
///   }
/// })
/// .then(response => response.json())
/// .then(results => {
///   results.forEach(result => {
///     console.log(`Result: ${result.label} (${result.confidence})`);
///   });
/// });
/// ```
#[tracing::instrument(skip(user, app_state), fields(user_id = %user.id, job_id = %path.as_ref()))]
pub async fn get_scan_results(
    user: AuthMiddleware,
    path: web::Path<Uuid>,
    app_state: web::Data<AppState>,
) -> impl Responder {
    let job_id = path.into_inner();
    let user_id = user.id;

    tracing::debug!(
        user.id = %user_id,
        job.id = %job_id,
        "Checking scan status"
    );

    tracing::debug!(
        user.id = %user_id,
        job.id = %job_id,
        "Fetching scan results"
    );

    // Check job ownership
    let job = sqlx::query!(
        "SELECT job_id FROM scan_jobs WHERE job_id = $1 AND user_id = $2",
        job_id,
        user_id
    )
    .fetch_optional(app_state.db.as_ref())
    .await;
    match job {
        Ok(Some(_)) => {
            let results = sqlx::query_as::<_, ScanResult>(
                r#"SELECT result_id, job_id, confidence, label, created_at FROM scan_results WHERE job_id = $1 ORDER BY created_at DESC"#,
            )
            .bind(job_id)
            .fetch_all(app_state.db.as_ref())
            .await;
            match results {
                Ok(res) => {
                    crate::tracing::log_event(
                        app_state.db.clone(),
                        "INFO",
                        "user_scan",
                        "Scan results retrieved",
                        Some(user_id),
                        Some(json!({
                            "user_id": user_id,
                            "job_id": job_id,
                            "result_count": res.len(),
                            "operation": "get_scan_results"
                        })),
                    )
                    .await;

                    tracing::info!(
                        user.id = %user_id,
                        job.id = %job_id,
                        result_count = res.len(),
                        "Scan results retrieved successfully"
                    );

                    HttpResponse::Ok().json(res)
                }
                Err(e) => {
                    crate::tracing::log_system_error(
                        app_state.db.clone(),
                        "user_scan",
                        &e,
                        Some(json!({
                            "operation": "get_scan_results",
                            "user_id": user_id,
                            "job_id": job_id,
                            "table": "scan_results"
                        })),
                        Some(user_id),
                    )
                    .await;

                    HttpResponse::InternalServerError()
                        .json(serde_json::json!({"error": "Failed to fetch results"}))
                }
            }
        }
        Ok(None) => {
            crate::tracing::log_security_event(
                app_state.db.clone(),
                "UNAUTHORIZED_ACCESS",
                "User attempted to access scan results for job they don't own",
                Some(user_id),
                None,
                Some(json!({
                    "user_id": user_id,
                    "requested_job_id": job_id,
                    "operation": "get_scan_results"
                })),
            )
            .await;

            HttpResponse::NotFound()
                .json(serde_json::json!({"error": "Job not found or not authorized"}))
        }
        Err(e) => {
            crate::tracing::log_system_error(
                app_state.db.clone(),
                "user_scan",
                &e,
                Some(json!({
                    "operation": "get_scan_results_ownership_check",
                    "user_id": user_id,
                    "job_id": job_id,
                    "table": "scan_jobs"
                })),
                Some(user_id),
            )
            .await;

            HttpResponse::InternalServerError().json(serde_json::json!({"error": "DB error"}))
        }
    }
}

/// Retrieves the current processing status of a specific scan job.
///
/// This endpoint provides real-time status information for monitoring scan job
/// progress. Users can poll this endpoint to track job completion and determine
/// when results are ready for retrieval.
///
/// # HTTP Method
/// `GET /api/user/scan/{job_id}/status`
///
/// # Authentication
/// Requires valid JWT token in Authorization header:
/// ```
/// Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
/// ```
///
/// # Path Parameters
/// - `job_id`: UUID of the scan job (e.g., `550e8400-e29b-41d4-a716-446655440000`)
///
/// # Request Body
/// None - this is a GET request with no body
///
/// # Success Response (200 OK)
/// Returns the current job status:
/// ```json
/// {
///   "status": "completed"
/// }
/// ```
///
/// # Possible Status Values
/// - `"pending"`: Job queued, waiting to start processing
/// - `"running"`: Currently being analyzed by the detection model
/// - `"completed"`: Analysis finished successfully, results available
/// - `"failed"`: Processing encountered an error
///
/// # Error Responses
/// - `401 Unauthorized`: Missing or invalid JWT token
/// - `404 Not Found`: Job doesn't exist or user doesn't own the job
/// - `500 Internal Server Error`: Database query errors
///
/// # Authorization
/// - Users can only check status for jobs they own
/// - Job ownership is verified by matching user_id from JWT token
/// - Attempting to check another user's job returns 404
///
/// # Polling Strategy
/// For real-time updates, clients should poll this endpoint:
/// - Poll every 5-10 seconds for pending/running jobs
/// - Stop polling once status becomes "completed" or "failed"
/// - Implement exponential backoff for failed requests
///
/// # Usage Example
/// ```javascript
/// const jobId = '550e8400-e29b-41d4-a716-446655440000';
///
/// function checkStatus() {
///   fetch(`/api/user/scan/${jobId}/status`, {
///     headers: {
///       'Authorization': 'Bearer ' + userToken
///     }
///   })
///   .then(response => response.json())
///   .then(data => {
///     console.log('Job status:', data.status);
///     if (data.status === 'pending' || data.status === 'running') {
///       setTimeout(checkStatus, 5000); // Poll again in 5 seconds
///     }
///   });
/// }
/// ```
#[tracing::instrument(skip(user, app_state), fields(user_id = %user.id, job_id = %path.as_ref()))]
pub async fn get_scan_status(
    user: AuthMiddleware,
    path: web::Path<Uuid>,
    app_state: web::Data<AppState>,
) -> impl Responder {
    let job_id = path.into_inner();
    let user_id = user.id;
    let row = sqlx::query!(
        r#"SELECT status FROM scan_jobs WHERE job_id = $1 AND user_id = $2"#,
        job_id,
        user_id
    )
    .fetch_optional(app_state.db.as_ref())
    .await;
    match row {
        Ok(Some(r)) => {
            crate::tracing::log_event(
                app_state.db.clone(),
                "DEBUG",
                "user_scan",
                "Scan status retrieved",
                Some(user_id),
                Some(json!({
                    "user_id": user_id,
                    "job_id": job_id,
                    "status": r.status,
                    "operation": "get_scan_status"
                })),
            )
            .await;

            HttpResponse::Ok().json(serde_json::json!({"status": r.status}))
        }
        Ok(None) => {
            crate::tracing::log_security_event(
                app_state.db.clone(),
                "UNAUTHORIZED_ACCESS",
                "User attempted to check status for job they don't own",
                Some(user_id),
                None,
                Some(json!({
                    "user_id": user_id,
                    "requested_job_id": job_id,
                    "operation": "get_scan_status"
                })),
            )
            .await;

            HttpResponse::NotFound().body("Job not found")
        }
        Err(e) => {
            crate::tracing::log_system_error(
                app_state.db.clone(),
                "user_scan",
                &e,
                Some(json!({
                    "operation": "get_scan_status",
                    "user_id": user_id,
                    "job_id": job_id,
                    "table": "scan_jobs"
                })),
                Some(user_id),
            )
            .await;

            HttpResponse::InternalServerError().finish()
        }
    }
}
