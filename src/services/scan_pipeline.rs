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
use crate::scraper::client::fetch_scraped_media;
use chrono::Utc;
use log::{error, info};
use sqlx::PgPool;
use uuid::Uuid;

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
pub async fn run_scan_pipeline(
    pool: PgPool,
    job_id: Uuid,
    target: String,
    user_id: Uuid,
) -> Result<(), sqlx::Error> {
    info!("Starting scan pipeline for job_id: {job_id} target: {target}");
    let media_urls = match fetch_scraped_media(&target, user_id).await {
        Ok(urls) => urls,
        Err(e) => {
            error!("Scraper error for job {job_id}: {e:?}");
            sqlx::query!(
                "UPDATE scan_jobs SET status = 'failed' WHERE job_id = $1",
                job_id
            )
            .execute(&pool)
            .await
            .ok();
            return Ok(());
        }
    };
    for media_url in media_urls {
        let (confidence, label) = match detect_deepfake(&media_url).await {
            Ok(res) => res,
            Err(e) => {
                error!("AI model error for job {job_id} url {media_url}: {e:?}",);
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
            error!("Failed to insert scan result: {e:?}");
        }
    }
    if let Err(e) = sqlx::query!(
        "UPDATE scan_jobs SET status = 'completed' WHERE job_id = $1",
        job_id
    )
    .execute(&pool)
    .await
    {
        error!("Failed to update scan job status: {e:?}");
    }
    info!("Completed scan pipeline for job_id: {job_id}");
    Ok(())
}
