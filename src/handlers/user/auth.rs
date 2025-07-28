//! User authentication endpoints: registration and login via Supabase Auth.
//!
//! These endpoints sanitize input and proxy requests to Supabase Auth REST API.

use crate::{AppState, SupabaseService, data::Role};
use actix_web::web;
use actix_web::{HttpRequest, HttpResponse, Responder};
use serde::Deserialize;
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(length(min = 2, max = 64))]
    pub name: String,
    #[validate(range(min = 13, max = 120))]
    pub age: i32,
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 8, max = 64))]
    pub password: String,
    #[validate(length(min = 1, max = 16))]
    pub gender: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 8, max = 64))]
    pub password: String,
}

/// Registers a new user account with Supabase Auth and creates associated profile data.
///
/// This endpoint handles complete user onboarding by:
/// 1. Validating the registration request data
/// 2. Creating a new account in Supabase Auth
/// 3. Inserting user profile information into the local database
/// 4. Setting up default user settings
///
/// # Request Body (JSON)
/// ```json
/// {
///   "name": "John Doe",           // String, 2-64 chars, user's display name
///   "age": 25,                    // Integer, 13-120, user's age
///   "email": "john@example.com",  // String, valid email format
///   "password": "SecurePass123",  // String, 8-64 chars, account password
///   "gender": "male"              // String, 1-16 chars, user's gender
/// }
/// ```
///
/// # Validation Rules
/// - `name`: Must be 2-64 characters long
/// - `age`: Must be between 13 and 120 years old
/// - `email`: Must be a valid email address format
/// - `password`: Must be 8-64 characters long (subject to Supabase password policies)
/// - `gender`: Must be 1-16 characters long
///
/// # Success Response (200 OK)
/// Returns the complete Supabase AuthResponse containing:
/// ```json
/// {
///   "access_token": "eyJhbGciOiJIUzI1NiIs...",
///   "token_type": "bearer",
///   "expires_in": 3600,
///   "expires_at": 1234567890,
///   "refresh_token": "v1.M2YwOTQxNzk...",
///   "user": { /* complete user object */ }
/// }
/// ```
///
/// # Error Responses
/// - `400 Bad Request`: Validation errors (invalid email, weak password, etc.)
/// - `422 Unprocessable Entity`: Email already exists or Supabase validation failure
/// - `500 Internal Server Error`: Database errors or Supabase service issues
///
/// # Side Effects
/// - Creates user account in Supabase Auth
/// - Inserts record into `user_profiles` table with profile information
/// - Inserts record into `user_settings` table with default preferences
/// - User is automatically logged in upon successful registration
#[tracing::instrument(skip(data, form), fields(email = %form.email, name = %form.name))]
pub async fn register(
    data: web::Data<AppState>,
    form: web::Json<RegisterRequest>,
    req: HttpRequest,
) -> impl Responder {
    let db = data.db.clone();
    if let Err(e) = form.validate() {
        // Logging is now automatic via tracing layer

        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": e.to_string()}));
    }
    tracing::info!(
        user.email = %form.email,
        user.name = %form.name,
        "Attempting user registration"
    );

    tracing::info!("Calling SupabaseService::register...");
    match SupabaseService::register(
        &data,
        &form.name,
        &form.email,
        &form.password,
        Role::User,
    )
    .await
    {
        Ok(res) => {
            let user_id = res.user.id;

            // Logging is now automatic via tracing layer

            // Insert user profile if registration returns a session (user created)
            if let Err(e) = sqlx::query(
                "INSERT INTO user_profiles (user_id, name, age, gender) VALUES ($1, $2, $3, $4) ON CONFLICT (user_id) DO NOTHING"
            )
            .bind(user_id)
            .bind(&form.name)
            .bind(form.age)
            .bind(&form.gender)
            .execute(db.as_ref())
            .await {
                // Logging is now automatic via tracing layer

                return HttpResponse::InternalServerError()
                    .json(serde_json::json!({"error": format!("profile insert failed: {}", e)}));
            }

            // Insert into user_settings with defaults
            if let Err(e) = sqlx::query(
                "INSERT INTO user_settings (user_id, email, scan_defaults)
                 VALUES ($1, $2, '{}'::jsonb)
                 ON CONFLICT (user_id) DO NOTHING",
            )
            .bind(user_id)
            .bind(&form.email)
            .execute(db.as_ref())
            .await
            {
                // Logging is now automatic via tracing layer

                return HttpResponse::InternalServerError()
                    .json(serde_json::json!({"error": format!("settings insert failed: {e}")}));
            }

            tracing::info!(
                user.id = %user_id,
                user.email = %form.email,
                "User registration completed successfully"
            );

            HttpResponse::Ok().json(res)
        }
        Err(e) => {
            // Logging is now automatic via tracing layer

            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": format!("registration failed: {:?}", e)}))
        }
    }
}

/// Authenticates an existing user with email and password via Supabase Auth.
///
/// This endpoint validates user credentials against Supabase Auth and returns
/// JWT tokens for authenticated API access. The user must have previously
/// registered an account.
///
/// # Request Body (JSON)
/// ```json
/// {
///   "email": "john@example.com",  // String, valid email format
///   "password": "SecurePass123"   // String, 8-64 chars, account password
/// }
/// ```
///
/// # Validation Rules
/// - `email`: Must be a valid email address format
/// - `password`: Must be 8-64 characters long
///
/// # Success Response (200 OK)
/// Returns the complete Supabase AuthResponse containing:
/// ```json
/// {
///   "access_token": "eyJhbGciOiJIUzI1NiIs...",  // JWT token for API access
///   "token_type": "bearer",                      // Token type (always "bearer")
///   "expires_in": 3600,                          // Token lifetime in seconds
///   "expires_at": 1234567890,                    // Unix timestamp of expiration
///   "refresh_token": "v1.M2YwOTQxNzk...",        // Token for refreshing access
///   "user": {                                    // Complete user profile
///     "id": "uuid-here",
///     "email": "john@example.com",
///     "user_metadata": { /* custom metadata */ },
///     /* ... other user fields ... */
///   }
/// }
/// ```
///
/// # Error Responses
/// - `400 Bad Request`: Validation errors (invalid email format, short password)
/// - `401 Unauthorized`: Invalid credentials (wrong email/password combination)
/// - `429 Too Many Requests`: Rate limit exceeded (too many failed attempts)
/// - `500 Internal Server Error`: Supabase service issues or network errors
///
/// # Usage Notes
/// - The `access_token` should be included in subsequent API requests as: `Authorization: Bearer {access_token}`
/// - Tokens expire after the time specified in `expires_in` (typically 1 hour)
/// - Use the `refresh_token` to obtain new access tokens when they expire
/// - User's `last_sign_in_at` timestamp is automatically updated by Supabase
#[tracing::instrument(skip(data, form), fields(email = %form.email))]
pub async fn login(
    data: web::Data<AppState>,
    form: web::Json<LoginRequest>,
    req: HttpRequest,
) -> impl Responder {
    if let Err(e) = form.validate() {
        return HttpResponse::BadRequest().json(serde_json::json!(e));
    }

    tracing::info!(
        user.email = %form.email,
        "Attempting user login"
    );

    match SupabaseService::login(&data, &form.email, &form.password).await {
        Ok(res) => {
            let user_id = res.user.id;

            // Logging is now automatic via tracing layer

            tracing::info!(
                user.id = %user_id,
                user.email = %form.email,
                "User login successful"
            );

            HttpResponse::Ok().json(res)
        }
        Err(e) => {
            // Logging is now automatic via tracing layer

            tracing::warn!(
                user.email = %form.email,
                error = ?e,
                "User login failed"
            );

            HttpResponse::InternalServerError().json(serde_json::json!(e))
        }
    }
}
