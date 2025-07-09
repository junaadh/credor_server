//! Health check endpoint for the credor backend API.
//!
//! Provides a simple endpoint to verify service liveness for monitoring and orchestration.

use actix_web::{HttpResponse, Responder};

/// Returns a JSON response indicating the API is healthy.
///
/// # Example
/// ```json
/// { "status": "ok" }
/// ```
pub async fn health_check() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({"status": "ok"}))
}
