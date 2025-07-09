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
/// Returns a JSON response indicating the API is healthy.
/// Adds tracing instrumentation and logs health check requests.
#[tracing::instrument]
pub async fn health_check() -> impl Responder {
    tracing::info!("Health check endpoint called");
    HttpResponse::Ok().json(serde_json::json!({"status": "ok"}))
}
