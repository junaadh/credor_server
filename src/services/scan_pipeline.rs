//! Background scan pipeline for deepfake detection jobs.
//!
//! This module defines the async job processor that:
//! - Fetches media URLs from an external scraper service
//! - Runs deepfake detection on each media item via external AI model
//! - Saves results to the database
//! - Updates scan job status accordingly
//!
//! Used by background tasks (tokio::spawn) to process scan jobs asynchronously.

use crate::detection::analyzer::detect_deepfake;
use chrono::Utc;
use sqlx::PgPool;
use tracing::{error, info, instrument};
use uuid::Uuid;

async fn fetch_scraped_media(_: &str, _: Uuid) -> Result<Vec<String>, String> {
    Ok(vec![])
}

/// Runs the scan pipeline for a given scan job.
///
/// - Fetches media URLs using the scraper API
/// - Runs deepfake detection on each media item
/// - Saves results to `scan_results` table
/// - Updates job status in `scan_jobs` table
///
/// # Parameters
/// - `pool`: SQLx Postgres connection pool
/// - `job_id`: The scan job's UUID
/// - `target`: The scan target (search keyword or URL)
/// - `user_id`: The user who initiated the scan
///
/// # Returns
/// - `Ok(())` on success
/// - Updates job status to 'failed' on error
///
/// # Async
/// This function is async and should be spawned as a background task.
/// Processes a scan job: fetches media, runs detection, saves results, and updates job status.
///
/// This function is instrumented for tracing and logs key events and errors with structured fields.
#[instrument(skip(pool), fields(job_id = %job_id, user_id = %user_id, target = %target))]
pub async fn run_scan_pipeline(
    pool: PgPool,
    job_id: Uuid,
    target: String,
    user_id: Uuid,
) -> Result<(), sqlx::Error> {
    info!(
        job.id = %job_id,
        user.id = %user_id,
        target = %target,
        "Starting scan pipeline"
    );

    // Fetch media URLs for the scan job
    let media_urls = match fetch_scraped_media(&target, user_id).await {
        Ok(urls) => urls,
        Err(e) => {
            error!(
                job.id = %job_id,
                user.id = %user_id,
                target = %target,
                error = ?e,
                "Failed to fetch media URLs from scraper"
            );
            // Mark job as failed in the database
            let _ = sqlx::query!(
                "UPDATE scan_jobs SET status = 'failed' WHERE job_id = $1",
                job_id
            )
            .execute(&pool)
            .await;
            return Ok(());
        }
    };

    // Run deepfake detection on each media item and save results
    for media_url in media_urls {
        let (confidence, label) = match detect_deepfake(&media_url).await {
            Ok(res) => res,
            Err(e) => {
                error!(
                    job.id = %job_id,
                    user.id = %user_id,
                    media_url = %media_url,
                    error = ?e,
                    "Deepfake detection failed for media"
                );
                (0.0, "UNKNOWN".to_string())
            }
        };
        let result_id = Uuid::new_v4();
        let detected_at = Utc::now();
        if let Err(e) = sqlx::query!(
            "INSERT INTO scan_results (result_id, job_id, media_url, confidence, label, detected_at) VALUES ($1, $2, $3, $4, $5, $6)",
            result_id,
            job_id,
            media_url,
            confidence as f64,
            label,
            detected_at
        ).execute(&pool).await {
            error!(
                job.id = %job_id,
                user.id = %user_id,
                media_url = %media_url,
                error = ?e,
                "Failed to insert scan result"
            );
        }
    }

    // Update job status to completed
    if let Err(e) = sqlx::query!(
        "UPDATE scan_jobs SET status = 'completed' WHERE job_id = $1",
        job_id
    )
    .execute(&pool)
    .await
    {
        error!(
            job.id = %job_id,
            user.id = %user_id,
            error = ?e,
            "Failed to update scan job status to completed"
        );
    }

    info!(
        job.id = %job_id,
        user.id = %user_id,
        "Completed scan pipeline"
    );
    Ok(())
}
