//! User settings endpoints for the credor deepfake detection backend.
//!
//! This module provides handlers for fetching and updating user settings.
//! All endpoints require JWT authentication and use structured tracing for observability.

use crate::models::UserSettings;
use crate::{AppState, auth_middleware::AuthMiddleware};
use crate::{SupabaseService, UpdateUserInput};
use actix_web::{HttpResponse, Responder, web};
use validator::Validate;

#[tracing::instrument(skip(user, app_state, payload), fields(user_id = %user.id))]
pub async fn patch_settings(
    user: AuthMiddleware,
    app_state: web::Data<AppState>,
    payload: web::Json<UpdateUserInput>,
) -> impl Responder {
    if let Err(e) = payload.validate() {
        return HttpResponse::BadRequest().json(serde_json::json!(e));
    }

    if let Err(e) = SupabaseService::update(&app_state, &user, payload.0).await {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": e.to_string() }));
    }

    HttpResponse::Ok().finish()
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
/// Retrieves the complete settings and preferences for the authenticated user.
/// Adds tracing instrumentation and logs key events and errors with structured fields.
#[tracing::instrument(skip(user, app_state), fields(user_id = %user.id))]
pub async fn get_settings(user: AuthMiddleware, app_state: web::Data<AppState>) -> impl Responder {
    let row = sqlx::query_as::<_, UserSettings>(
        r#"SELECT email, scan_defaults, theme, notifications, language, timezone FROM user_settings WHERE user_id = $1"#,
    )
    .bind(user.id)
    .fetch_optional(app_state.db.as_ref())
    .await;
    match row {
        Ok(Some(settings)) => {
            tracing::info!(
                user.id = %user.id,
                "User settings retrieved successfully"
            );
            HttpResponse::Ok().json(settings)
        }
        Ok(None) => {
            tracing::warn!(
                user.id = %user.id,
                "User settings not found"
            );
            HttpResponse::NotFound().json(serde_json::json!({"error": "Settings not found"}))
        }
        Err(e) => {
            tracing::error!(
                user.id = %user.id,
                error = ?e,
                "Database error during user settings retrieval"
            );
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "DB error"}))
        }
    }
}
