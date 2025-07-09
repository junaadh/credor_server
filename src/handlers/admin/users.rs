//! Admin user management endpoints for comprehensive user oversight.
//!
//! This module provides administrative endpoints for viewing and managing user accounts,
//! profiles, and associated data. Includes user listing, profile inspection, and
//! account management capabilities for admin moderation and support purposes.

use crate::handlers::admin::guard::admin_guard;
use crate::{AppState, auth_middleware::AuthMiddleware};
use actix_web::{HttpResponse, Responder, web};
use serde::Serialize;

/// Represents a user profile as seen by an admin.
#[derive(Serialize)]
pub struct AdminUserProfile {
    /// The user's unique identifier.
    pub user_id: uuid::Uuid,
    /// The user's display name (optional).
    pub name: Option<String>,
    /// The user's email address.
    pub email: String,
    /// The user's age (optional).
    pub age: Option<i32>,
    /// The user's gender (optional).
    pub gender: Option<String>,
}

/// Retrieves a comprehensive list of all user profiles and account information for admin review.
///
/// This endpoint provides administrators with complete visibility into user accounts,
/// including profile data from both the local database and Supabase Auth. Used for
/// user management, support, moderation, and system administration tasks.
///
/// # HTTP Method
/// `GET /api/admin/users`
///
/// # Authentication
/// Requires valid JWT token with admin role in Authorization header:
/// ```
/// Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
/// ```
///
/// # Request Parameters
/// None - returns all users in the system
///
/// # Request Body
/// None - this is a GET request with no body
///
/// # Success Response (200 OK)
/// Returns an array of user profiles with account information:
/// ```json
/// [
///   {
///     "user_id": "123e4567-e89b-12d3-a456-426614174000",
///     "name": "John Doe",
///     "email": "john.doe@example.com",
///     "age": 28,
///     "gender": "male"
///   },
///   {
///     "user_id": "234f5678-f89c-23e4-b567-537725285111",
///     "name": "Jane Smith",
///     "email": "jane.smith@example.com",
///     "age": 32,
///     "gender": "female"
///   },
///   {
///     "user_id": "345g6789-g89d-34f5-c678-648836396222",
///     "name": null,
///     "email": "user@domain.com",
///     "age": null,
///     "gender": null
///   }
/// ]
/// ```
///
/// # Response Fields
/// - `user_id`: Unique UUID identifier for the user account
/// - `name`: User's display name (may be null if not provided)
/// - `email`: User's email address from Supabase Auth
/// - `age`: User's age (may be null if not provided)
/// - `gender`: User's gender identity (may be null if not provided)
///
/// # Error Responses
/// - `401 Unauthorized`: Missing or invalid JWT token
/// - `403 Forbidden`: User lacks admin privileges
/// - `500 Internal Server Error`: Database query failures or connection issues
///
/// # Data Sources
/// This endpoint joins data from:
/// - `user_profiles` table: Profile information (name, age, gender)
/// - `auth.users` table: Supabase Auth data (email, account status)
///
/// # Null Value Handling
/// - Email defaults to empty string if missing from Supabase
/// - Profile fields (name, age, gender) may be null for incomplete profiles
/// - Users without profile records won't appear in results
///
/// # Performance Notes
/// - Queries all users without pagination
/// - Consider adding pagination for large user bases
/// - Uses JOIN operation between local and Supabase tables
/// - Results are not cached - queries database on each request
///
/// # Admin Use Cases
/// - User account management and support
/// - Demographic analysis and reporting
/// - Account verification and moderation
/// - System administration and user auditing
/// - Identifying incomplete or problematic profiles
///
/// # Privacy Considerations
/// - Contains personally identifiable information (PII)
/// - Should be logged for audit purposes
/// - Consider data retention policies
/// - Ensure compliance with privacy regulations
///
/// # Usage Example
/// ```javascript
/// fetch('/api/admin/users', {
///   headers: {
///     'Authorization': 'Bearer ' + adminToken
///   }
/// })
/// .then(response => response.json())
/// .then(users => {
///   console.log(`Found ${users.length} registered users`);
///   users.forEach(user => {
///     console.log(`${user.email}: ${user.name || 'No name'}`);
///   });
/// });
/// ```
///
/// # Future Enhancements
/// - Add pagination support for large datasets
/// - Include user activity metrics (last login, scan count)
/// - Add filtering by registration date, activity status
/// - Include user settings and preferences overview
///
/// # Authorization
/// Requires admin privileges verified through `admin_guard()`.
/// Retrieves a comprehensive list of all user profiles and account information for admin review.
/// Adds tracing instrumentation and logs key events and errors with structured fields.
#[tracing::instrument(skip(user, app_state), fields(admin_id = %user.id))]
pub async fn get_users(user: AuthMiddleware, app_state: web::Data<AppState>) -> impl Responder {
    if let Err(resp) = admin_guard(&user) {
        return resp;
    }
    let rows = sqlx::query!(
        r#"
        SELECT user_profiles.user_id, user_profiles.name, auth.users.email, user_profiles.age, user_profiles.gender
           FROM user_profiles JOIN auth.users ON user_profiles.user_id = auth.users.id"#
    )
    .fetch_all(app_state.db.as_ref())
    .await;
    match rows {
        Ok(users) => {
            let mapped: Vec<AdminUserProfile> = users
                .into_iter()
                .map(|u| AdminUserProfile {
                    user_id: u.user_id,
                    name: u.name,
                    email: u.email.unwrap_or_default(),
                    age: u.age,
                    gender: u.gender,
                })
                .collect();
            tracing::info!(
                admin_id = %user.id,
                user_count = mapped.len(),
                "Admin fetched user list successfully"
            );
            HttpResponse::Ok().json(mapped)
        }
        Err(e) => {
            tracing::error!(
                admin_id = %user.id,
                error = ?e,
                "Failed to fetch users for admin"
            );
            HttpResponse::InternalServerError()
                .json(serde_json::json!({ "error": "Failed to fetch users" }))
        }
    }
}
