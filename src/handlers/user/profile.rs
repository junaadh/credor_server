//! User profile management endpoints.
//!
//! Provides handlers for updating and retrieving user profile information.

use crate::{AppState, auth_middleware::AuthMiddleware};
use actix_web::{HttpResponse, Responder, web};
use serde::{Deserialize, Serialize};

/// Request payload for updating a user's profile.
#[derive(Debug, Deserialize)]
pub struct UpdateProfileRequest {
    /// The user's display name.
    pub name: String,
    /// The user's age (must be between 13 and 130).
    pub age: i32,
    /// The user's gender.
    pub gender: String,
}

/// Response payload for returning a user's profile.
#[derive(Debug, Serialize)]
pub struct UserProfileResponse {
    /// The user's display name.
    pub name: String,
    /// The user's age.
    pub age: i32,
    /// The user's gender.
    pub gender: String,
}

/// Updates the authenticated user's profile information in the database.
///
/// This endpoint allows users to modify their profile data including name, age, and gender.
/// The user is identified from the JWT token, ensuring users can only update their own profiles.
///
/// # HTTP Method
/// `PUT /api/user/profile`
///
/// # Authentication
/// Requires valid JWT token in Authorization header:
/// ```
/// Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
/// ```
///
/// # Request Body (JSON)
/// ```json
/// {
///   "name": "Jane Smith",        // String, user's display name
///   "age": 28,                   // Integer, must be between 13-130
///   "gender": "female"           // String, user's gender identity
/// }
/// ```
///
/// # Validation Rules
/// - `name`: Required string for display purposes
/// - `age`: Must be between 13 and 130 years old (inclusive)
/// - `gender`: Required string for demographic data
/// - All fields are required and cannot be null
///
/// # Success Response (200 OK)
/// Returns the updated profile information:
/// ```json
/// {
///   "name": "Jane Smith",
///   "age": 28,
///   "gender": "female"
/// }
/// ```
///
/// # Error Responses
/// - `400 Bad Request`: Invalid age (outside 13-130 range) or malformed request
/// - `401 Unauthorized`: Missing or invalid JWT token
/// - `404 Not Found`: User profile not found in database
/// - `500 Internal Server Error`: Database errors or incomplete profile data
///
/// # Database Operation
/// Updates the `user_profiles` table with new values and returns the updated record.
/// Uses `RETURNING` clause to fetch the updated data in a single query.
///
/// # Security Notes
/// - Users can only update their own profile (user ID from JWT token)
/// - Profile updates are immediately reflected in the database
/// - No sensitive data (email, password) is modified through this endpoint
///
/// # Usage Example
/// ```javascript
/// fetch('/api/user/profile', {
///   method: 'PUT',
///   headers: {
///     'Content-Type': 'application/json',
///     'Authorization': 'Bearer ' + userToken
///   },
///   body: JSON.stringify({
///     name: 'Updated Name',
///     age: 30,
///     gender: 'non-binary'
///   })
/// });
/// ```
pub async fn update_profile(
    user: AuthMiddleware,
    app_state: web::Data<AppState>,
    payload: web::Json<UpdateProfileRequest>,
) -> impl Responder {
    if !(13..=130).contains(&payload.age) {
        return HttpResponse::BadRequest().json(serde_json::json!("Invalid age"));
    }

    let res = sqlx::query!(
        r#"UPDATE user_profiles SET name = $1, age = $2, gender = $3 WHERE user_id = $4 RETURNING name, age, gender"#,
        payload.name,
        payload.age,
        payload.gender,
        user.id
    )
    .fetch_optional(app_state.db.as_ref())
    .await;
    match res {
        Ok(Some(row)) => {
            if let (Some(name), Some(age), Some(gender)) = (row.name, row.age, row.gender) {
                HttpResponse::Ok().json(UserProfileResponse { name, age, gender })
            } else {
                HttpResponse::InternalServerError().json(serde_json::json!(
                    "Incomplete profile data returned from DB"
                ))
            }
        }
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!("Profile not found")),
        Err(_) => HttpResponse::InternalServerError().json(serde_json::json!("DB error")),
    }
}
