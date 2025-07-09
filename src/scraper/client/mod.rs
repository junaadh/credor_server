//! Scraper integration client for fetching media URLs.
//!
//! Provides async functions and error types for communicating with the external scraper service.

use reqwest::Client;
use serde::Deserialize;
use thiserror::Error;
use uuid::Uuid;

/// Errors that can occur when communicating with the scraper service.
#[derive(Debug, Error)]
pub enum ScraperError {
    /// HTTP error from reqwest.
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    /// The scraper returned an invalid or unexpected response.
    #[error("Invalid response from scraper")]
    InvalidResponse,
}

#[derive(Deserialize)]
struct ScraperResponse {
    media_urls: Vec<String>,
}

/// Fetches media URLs from the scraper service for a given keyword and user.
///
/// # Arguments
/// * `keyword` - The search keyword to scrape for.
/// * `user_id` - The UUID of the requesting user.
///
/// # Errors
/// Returns [`ScraperError`] if the HTTP request fails or the response is invalid.
///
/// # Returns
/// A vector of media URLs on success.
pub async fn fetch_scraped_media(
    keyword: &str,
    user_id: Uuid,
) -> Result<Vec<String>, ScraperError> {
    let client = Client::new();
    let url = format!("http://localhost:8001/api/scrape?keyword={keyword}&user={user_id}");
    let resp = client.get(&url).send().await?;
    if !resp.status().is_success() {
        return Err(ScraperError::InvalidResponse);
    }
    let json: ScraperResponse = resp
        .json()
        .await
        .map_err(|_| ScraperError::InvalidResponse)?;
    Ok(json.media_urls)
}
