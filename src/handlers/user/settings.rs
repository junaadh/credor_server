//! User settings endpoints for the credor deepfake detection backend.
//!
//! This module provides handlers for fetching and updating user settings.
//! All endpoints require JWT authentication.

use crate::models::UserSettings;
use crate::{AppState, auth_middleware::AuthMiddleware};
use actix_web::{HttpResponse, Responder, web};
use serde::Deserialize;

/// Partial update payload for user settings.
#[derive(Debug, Deserialize)]
pub struct UserSettingsPatch {
    /// UI theme (optional)
    pub theme: Option<String>,
    /// Notification preferences (optional, JSON)
    pub notifications: Option<serde_json::Value>,
    /// Default scan parameters (optional, JSON)
    pub scan_defaults: Option<serde_json::Value>,
    /// Preferred language (optional)
    pub language: Option<String>,
    /// Preferred timezone (optional)
    pub timezone: Option<String>,
}

/// Partially updates the authenticated user's settings and preferences.
///
/// This endpoint allows users to update any subset of their settings without
/// requiring all fields. Only provided fields are updated, leaving others unchanged.
/// The user is identified from the JWT token.
///
/// # HTTP Method
/// `PATCH /api/user/settings`
///
/// # Authentication
/// Requires valid JWT token in Authorization header:
/// ```
/// Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
/// ```
///
/// # Request Body (JSON)
/// All fields are optional - include only the settings you want to update:
/// ```json
/// {
///   "theme": "dark",                           // Optional: UI theme preference
///   "language": "en",                          // Optional: Interface language
///   "timezone": "America/New_York",            // Optional: User's timezone
///   "notifications": {                         // Optional: Notification preferences
///     "email_alerts": true,
///     "push_notifications": false,
///     "weekly_summary": true
///   },
///   "scan_defaults": {                         // Optional: Default scan parameters
///     "confidence_threshold": 0.8,
///     "notify_on_completion": true,
///     "auto_delete_after_days": 30
///   }
/// }
/// ```
///
/// # Field Descriptions
/// - `theme`: UI appearance ("light", "dark", "auto")
/// - `language`: ISO language code for interface localization
/// - `timezone`: IANA timezone identifier for timestamp display
/// - `notifications`: JSON object with notification preferences
/// - `scan_defaults`: JSON object with default scanning parameters
///
/// # Success Response (200 OK)
/// Returns the complete updated settings:
/// ```json
/// {
///   "email": "user@example.com",
///   "theme": "dark",
///   "language": "en",
///   "timezone": "America/New_York",
///   "notifications": { /* notification settings */ },
///   "scan_defaults": { /* scan defaults */ }
/// }
/// ```
///
/// # Error Responses
/// - `400 Bad Request`: No fields provided for update or invalid JSON
/// - `401 Unauthorized`: Missing or invalid JWT token
/// - `404 Not Found`: User settings record not found
/// - `500 Internal Server Error`: Database errors or update failure
///
/// # Partial Update Behavior
/// - Only specified fields are updated in the database
/// - Unspecified fields retain their current values
/// - JSON fields (notifications, scan_defaults) are completely replaced if provided
/// - Empty request body results in 400 error
///
/// # Usage Example
/// ```javascript
/// fetch('/api/user/settings', {
///   method: 'PATCH',
///   headers: {
///     'Content-Type': 'application/json',
///     'Authorization': 'Bearer ' + userToken
///   },
///   body: JSON.stringify({
///     theme: 'dark',
///     notifications: {
///       email_alerts: false,
///       push_notifications: true
///     }
///   })
/// });
/// ```
pub async fn patch_settings(
    user: AuthMiddleware,
    app_state: web::Data<AppState>,
    payload: web::Json<UserSettingsPatch>,
) -> impl Responder {
    // Build dynamic SQL for only provided fields
    let mut sets = vec![];
    let mut values: Vec<sqlx::types::Json<serde_json::Value>> = vec![];
    let mut idx = 1;
    if let Some(theme) = &payload.theme {
        sets.push(format!("theme = ${idx}"));
        values.push(sqlx::types::Json(serde_json::json!(theme)));
        idx += 1;
    }
    if let Some(notifications) = &payload.notifications {
        sets.push(format!("notifications = ${idx}"));
        values.push(sqlx::types::Json(notifications.clone()));
        idx += 1;
    }
    if let Some(scan_defaults) = &payload.scan_defaults {
        sets.push(format!("scan_defaults = ${idx}"));
        values.push(sqlx::types::Json(scan_defaults.clone()));
        idx += 1;
    }
    if let Some(language) = &payload.language {
        sets.push(format!("language = ${idx}"));
        values.push(sqlx::types::Json(serde_json::json!(language)));
        idx += 1;
    }
    if let Some(timezone) = &payload.timezone {
        sets.push(format!("timezone = ${idx}"));
        values.push(sqlx::types::Json(serde_json::json!(timezone)));
        idx += 1;
    }
    if sets.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!("No fields to update"));
    }
    let set_clause = sets.join(", ");
    let sql = format!(
        "UPDATE user_settings SET {set_clause} WHERE user_id = $${idx} RETURNING email, scan_defaults, theme, notifications, language, timezone"
    );
    let mut query = sqlx::query_as::<_, UserSettings>(&sql);
    for val in &values {
        query = query.bind(val);
    }
    query = query.bind(user.id);
    let row = query.fetch_optional(app_state.db.as_ref()).await;
    match row {
        Ok(Some(settings)) => HttpResponse::Ok().json(settings),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!("Settings not found")),
        Err(_) => HttpResponse::InternalServerError().json(serde_json::json!("DB error")),
    }
}

/// Retrieves the complete settings and preferences for the authenticated user.
///
/// This endpoint returns all user settings including theme preferences, notification
/// settings, language/timezone configuration, and default scan parameters.
///
/// # HTTP Method
/// `GET /api/user/settings`
///
/// # Authentication
/// Requires valid JWT token in Authorization header:
/// ```
/// Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
/// ```
///
/// # Request Parameters
/// None - returns settings for the authenticated user
///
/// # Request Body
/// None - this is a GET request with no body
///
/// # Success Response (200 OK)
/// Returns the complete user settings object:
/// ```json
/// {
///   "email": "user@example.com",
///   "theme": "dark",
///   "language": "en",
///   "timezone": "America/New_York",
///   "notifications": {
///     "email_alerts": true,
///     "push_notifications": false,
///     "weekly_summary": true,
///     "scan_completion": true
///   },
///   "scan_defaults": {
///     "confidence_threshold": 0.8,
///     "notify_on_completion": true,
///     "auto_delete_after_days": 30,
///     "priority": "normal"
///   }
/// }
/// ```
///
/// # Error Responses
/// - `401 Unauthorized`: Missing or invalid JWT token
/// - `404 Not Found`: User settings not found (user may need to update settings first)
/// - `500 Internal Server Error`: Database query errors
///
/// # Field Descriptions
/// - `email`: User's email address (from user account)
/// - `theme`: Current UI theme preference
/// - `language`: Interface language setting
/// - `timezone`: User's timezone for timestamp display
/// - `notifications`: JSON object with notification preferences
/// - `scan_defaults`: JSON object with default scanning parameters
///
/// # Default Values
/// If no settings exist for the user, a 404 is returned. Users should:
/// 1. Use PATCH endpoint to create initial settings
/// 2. Provide default values in the application if settings are missing
///
/// # Usage Example
/// ```javascript
/// fetch('/api/user/settings', {
///   headers: {
///     'Authorization': 'Bearer ' + userToken
///   }
/// })
/// .then(response => response.json())
/// .then(settings => {
///   console.log('User theme:', settings.theme);
///   console.log('Notifications enabled:', settings.notifications.email_alerts);
/// })
/// .catch(error => {
///   if (error.status === 404) {
///     console.log('No settings found, using defaults');
///   }
/// });
/// ```
pub async fn get_settings(user: AuthMiddleware, app_state: web::Data<AppState>) -> impl Responder {
    let row = sqlx::query_as::<_, UserSettings>(
        r#"SELECT email, scan_defaults, theme, notifications, language, timezone FROM user_settings WHERE user_id = $1"#,
    )
    .bind(user.id)
    .fetch_optional(app_state.db.as_ref())
    .await;
    match row {
        Ok(Some(settings)) => HttpResponse::Ok().json(settings),
        Ok(None) => {
            HttpResponse::NotFound().json(serde_json::json!({"error": "Settings not found"}))
        }
        Err(_) => {
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "DB error"}))
        }
    }
}
