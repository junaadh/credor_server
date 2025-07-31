use actix_web::{HttpResponse, Responder, web};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{error, info, instrument};
use uuid::Uuid;

use crate::{AppState, user::scan::ScanResult};

#[derive(Debug, Serialize, Deserialize)]
pub struct AiJobPartialDone {
    confidence: f64,
    job_id: Uuid,
    user_id: Uuid,
    detected_at: DateTime<Utc>,
    label: String,
    serial_id: u64,
    media_url: String,
    post_url: String,
}

#[instrument(skip(app_state, payload))]
pub async fn job_partial_done(
    app_state: web::Data<AppState>,
    payload: web::Json<AiJobPartialDone>,
) -> impl Responder {
    let result_id = Uuid::new_v4();
    info!("job partially completed: {result_id}");

    if let Err(e) = sqlx::query!(
        "INSERT INTO scan_results (result_id, job_id, user_id, confidence, label, detected_at, media_url, post_url) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        result_id,
        payload.job_id,
        payload.user_id,
        payload.confidence as f64,
        payload.label,
        payload.detected_at,
        payload.media_url,
        payload.post_url
    ).execute(app_state.db.as_ref()).await {
        info!(
            job.id = %payload.job_id,
            error = ?e,
            "failed to insert scan result"
        );
    }

    if let Err(e) = sqlx::query!(
        "UPDATE scan_jobs SET status = 'running' WHERE job_id = $1",
        payload.job_id
    )
    .execute(app_state.db.as_ref())
    .await
    {
        info!(
            job.id = %payload.job_id,
            error = ?e,
            "failed to update scan job status to running",
        );
    }

    info!(
        job.id = %payload.job_id,
        "Proceeding with scan pipeline"
    );

    HttpResponse::Ok().json(serde_json::json!(ScanResult {
        result_id,
        job_id: payload.job_id,
        confidence: payload.confidence,
        label: payload.label.clone(),
        detected_at: payload.detected_at,
        media_url: payload.media_url.clone(),
        post_url: payload.post_url.clone(),
    }))
}

#[allow(clippy::async_yields_async)]
#[instrument(skip(app_state), fields(job_id = %job_id))]
pub async fn job_done(
    app_state: web::Data<AppState>,
    job_id: web::Path<Uuid>,
) -> impl Responder {
    if let Err(e) = sqlx::query!(
        "UPDATE scan_jobs SET status = 'completed' WHERE job_id = $1",
        *job_id
    )
    .execute(app_state.db.as_ref())
    .await
    {
        error!(
            job.id = %job_id,
            error = ?e,
            "failed to update scan job status to completed",
        );
    }

    info!(
        job.id = %job_id,
        "completed with scan pipeline"
    );

    HttpResponse::Ok()
}
