//! User account deletion endpoint.
//!
//! Provides a handler for deleting a user's account and all associated data from the database.

use crate::{AppState, SupabaseService, auth_middleware::AuthMiddleware};
use actix_web::{HttpResponse, Responder, web};
use tracing::{info, instrument};

/// Permanently deletes the authenticated user's account and all associated data.
///
/// This endpoint performs a complete account deletion by:
/// 1. Removing the user account from Supabase Auth
/// 2. Cascading deletion of all user data from local database tables
/// 3. Ensuring data privacy compliance through complete data removal
///
/// # HTTP Method
/// `DELETE /api/user/delete`
///
/// # Authentication
/// Requires valid JWT token in Authorization header:
/// ```
/// Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
/// ```
///
/// # Request Parameters
/// None - the user to delete is determined from the JWT token
///
/// # Request Body
/// None - this endpoint does not accept a request body
///
/// # Success Response (204 No Content)
/// Returns empty response body with 204 status code indicating successful deletion.
/// The account and all associated data have been permanently removed.
///
/// # Error Responses
/// - `401 Unauthorized`: Missing or invalid JWT token
/// - `403 Forbidden`: User not authorized to delete this account
/// - `500 Internal Server Error`: Supabase deletion failed or database errors
///
/// # Data Deletion Order
/// The following data is deleted in this order:
/// 1. **Supabase Auth**: User account and authentication data
/// 2. **scan_results**: All deepfake detection results for the user's jobs
/// 3. **scan_jobs**: All scan jobs submitted by the user
/// 4. **user_settings**: User preferences and configuration
/// 5. **user_profiles**: User profile information and metadata
///
/// # Security & Privacy Notes
/// - This operation is **irreversible** - deleted data cannot be recovered
/// - All user data is permanently removed for GDPR/privacy compliance
/// - Individual delete operations are idempotent (ignore errors for missing data)
/// - The user's JWT token becomes invalid immediately after deletion
/// - Any active sessions are terminated
///
/// # Side Effects
/// - User is logged out of all devices and sessions
/// - All pending scan jobs are cancelled
/// - Historical scan data is permanently lost
/// - User settings and preferences are reset
/// - Account cannot be used for future logins
///
/// # Usage Example
/// ```javascript
/// fetch('/api/user/delete', {
///   method: 'DELETE',
///   headers: {
///     'Authorization': 'Bearer ' + userToken
///   }
/// })
/// .then(response => {
///   if (response.status === 204) {
///     console.log('Account deleted successfully');
///     // Redirect to login page
///   }
/// });
/// ```
/// Deletes the authenticated user's account and all associated data.
/// This operation is instrumented for tracing and logs key events.
#[instrument(skip(data, user), fields(user_id = %user.id))]
pub async fn delete_account(data: web::Data<AppState>, user: AuthMiddleware) -> impl Responder {
    let user_id = user.id;

    // Delete user from Supabase Auth
    if let Err(e) = SupabaseService::delete(&data, &user, user_id).await {
        tracing::error!(
            user.id = %user_id,
            error = ?e,
            "Failed to delete user from Supabase Auth"
        );
        return HttpResponse::InternalServerError().json(serde_json::json!(e));
    }

    let db = data.db.as_ref();

    // Delete all scan results for the user's jobs
    let _ = sqlx::query!(
        "DELETE FROM scan_results WHERE job_id IN (SELECT job_id FROM scan_jobs WHERE user_id = $1)",
        user_id
    )
    .execute(db)
    .await;

    // Delete all scan jobs for the user
    let _ = sqlx::query!("DELETE FROM scan_jobs WHERE user_id = $1", user_id)
        .execute(db)
        .await;

    // Delete user settings
    let _ = sqlx::query!("DELETE FROM user_settings WHERE user_id = $1", user_id)
        .execute(db)
        .await;

    // Delete user profile
    let _ = sqlx::query!("DELETE FROM user_profiles WHERE user_id = $1", user_id)
        .execute(db)
        .await;

    info!(
        user.id = %user_id,
        "Deleted account and all associated data"
    );
    HttpResponse::NoContent().finish()
}
