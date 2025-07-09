//! Deepfake detection model integration client.
//!
//! Provides async functions and error types for communicating with the external AI detection model service.

use reqwest::Client;
use serde::Deserialize;
use thiserror::Error;

/// Errors that can occur when communicating with the AI model service.
#[derive(Debug, Error)]
pub enum AiModelError {
    /// HTTP error from reqwest.
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    /// The model returned an invalid or unexpected response.
    #[error("Invalid response from AI model")] 
    InvalidResponse,
    /// The model timed out or was unreachable.
    #[error("Timeout or unreachable model")] 
    Timeout,
}

#[derive(Deserialize)]
struct ModelResponse {
    confidence: f32,
    label: String,
}

/// Sends a media URL to the AI model service for deepfake detection.
///
/// # Arguments
/// * `media_url` - The URL of the media to analyze.
///
/// # Errors
/// Returns [`AiModelError`] if the HTTP request fails or the response is invalid.
///
/// # Returns
/// A tuple of (confidence, label) on success.
pub async fn detect_deepfake(media_url: &str) -> Result<(f32, String), AiModelError> {
    let client = Client::new();
    let resp = client.post("http://localhost:8002/api/analyze")
        .json(&serde_json::json!({"url": media_url}))
        .send().await.map_err(AiModelError::Http)?;
    if !resp.status().is_success() {
        return Ok((0.0, "UNKNOWN".to_string()));
    }
    let model: ModelResponse = resp.json().await.map_err(|_| AiModelError::InvalidResponse)?;
    Ok((model.confidence, model.label))
}
