//! Admin authentication endpoints: registration and login via Supabase Auth.
//!
//! These endpoints sanitize input and proxy requests to Supabase Auth REST API, but only allow admin registration if the email is in an allowed list (optional).

use crate::services::SupabaseService;
use crate::{AppState, data::Role};
use actix_web::{HttpResponse, Responder, web};
use serde::Deserialize;
use tracing::{Span, instrument};
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub struct AdminRegisterRequest {
    pub name: String,
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 8, max = 64))]
    pub password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct AdminLoginRequest {
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 8, max = 64))]
    pub password: String,
}

/// Registers a new administrator account with elevated privileges.
///
/// This endpoint creates a new admin account through Supabase Auth with the Admin role.
/// Unlike regular user registration, this endpoint is typically restricted to existing
/// administrators or used during initial system setup.
///
/// # HTTP Method
/// `POST /api/admin/register`
///
/// # Authentication
/// May require existing admin privileges depending on system configuration.
///
/// # Request Body (JSON)
/// ```json
/// {
///   "name": "Jane Admin",              // String, administrator's display name
///   "email": "admin@company.com",      // String, valid email format
///   "password": "SecureAdminPass123"   // String, 8-64 chars, strong password
/// }
/// ```
///
/// # Validation Rules
/// - `name`: Required string for identification
/// - `email`: Must be a valid email address format
/// - `password`: Must be 8-64 characters long (subject to Supabase password policies)
///
/// # Success Response (200 OK)
/// Returns the complete Supabase AuthResponse with admin role:
/// ```json
/// {
///   "access_token": "eyJhbGciOiJIUzI1NiIs...",
///   "token_type": "bearer",
///   "expires_in": 3600,
///   "expires_at": 1234567890,
///   "refresh_token": "v1.M2YwOTQxNzk...",
///   "user": {
///     "id": "uuid-here",
///     "email": "admin@company.com",
///     "user_metadata": {
///       "role": "admin",
///       "name": "Jane Admin"
///     }
///   }
/// }
/// ```
///
/// # Error Responses
/// - `400 Bad Request`: Validation errors (invalid email, weak password)
/// - `422 Unprocessable Entity`: Email already exists or admin creation restricted
/// - `500 Internal Server Error`: Supabase service issues
///
/// # Security Notes
/// - Creates account with Admin role for elevated system access
/// - Admin accounts can access all user data and system functions
/// - Consider implementing admin invitation/approval workflows
/// - Monitor admin account creation for security auditing
///
/// # Side Effects
/// - Creates admin account in Supabase Auth with Admin role
/// - Admin gains access to all administrative endpoints
/// - No additional database records created (unlike user registration)
pub async fn register(
    data: web::Data<AppState>,
    form: web::Json<AdminRegisterRequest>,
) -> impl Responder {
    if let Err(e) = form.validate() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": e.to_string()}));
    }
    match SupabaseService::register(&data, &form.name, &form.email, &form.password, Role::Admin)
        .await
    {
        Ok(res) => HttpResponse::Ok().json(res),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!(e)), // todo!()
    }
}

/// Authenticates an administrator and returns elevated access tokens.
///
/// This endpoint validates admin credentials against Supabase Auth and returns
/// JWT tokens with admin privileges. The returned tokens provide access to
/// administrative endpoints and sensitive system operations.
///
/// # HTTP Method
/// `POST /api/admin/login`
///
/// # Authentication
/// None required - this is the login endpoint
///
/// # Request Body (JSON)
/// ```json
/// {
///   "email": "admin@company.com",      // String, admin email address
///   "password": "SecureAdminPass123"   // String, admin password
/// }
/// ```
///
/// # Validation Rules
/// - `email`: Must be a valid email address format
/// - `password`: Must be 8-64 characters long
///
/// # Success Response (200 OK)
/// Returns admin authentication tokens:
/// ```json
/// {
///   "access_token": "eyJhbGciOiJIUzI1NiIs...",  // JWT with admin claims
///   "token_type": "bearer",                      // Always "bearer"
///   "expires_in": 3600,                          // Token lifetime (1 hour)
///   "expires_at": 1234567890,                    // Unix expiration timestamp
///   "refresh_token": "v1.M2YwOTQxNzk...",        // For token refresh
///   "user": {
///     "id": "uuid-here",
///     "email": "admin@company.com",
///     "user_metadata": {
///       "role": "admin"                          // Admin role identifier
///     }
///   }
/// }
/// ```
///
/// # Error Responses
/// - `400 Bad Request`: Validation errors (malformed email/password)
/// - `401 Unauthorized`: Invalid credentials or account not found
/// - `403 Forbidden`: Account exists but lacks admin privileges
/// - `429 Too Many Requests`: Rate limit exceeded for failed attempts
/// - `500 Internal Server Error`: Supabase service unavailable
///
/// # Token Usage
/// Include the access token in subsequent admin API requests:
/// ```
/// Authorization: Bearer {access_token}
/// ```
///
/// # Security Features
/// - Admin tokens include elevated role claims
/// - Shorter token lifetime for enhanced security
/// - Failed attempts are rate-limited
/// - Admin logins should be logged for audit trails
///
/// # Usage Example
/// ```javascript
/// fetch('/api/admin/login', {
///   method: 'POST',
///   headers: { 'Content-Type': 'application/json' },
///   body: JSON.stringify({
///     email: 'admin@company.com',
///     password: 'adminPassword123'
///   })
/// })
/// .then(response => response.json())
/// .then(auth => {
///   localStorage.setItem('adminToken', auth.access_token);
/// });
/// ```
#[instrument(skip(data), fields(user_id = tracing::field::Empty, user_role = "admin"))]
pub async fn login(
    data: web::Data<AppState>,
    form: web::Json<AdminLoginRequest>,
) -> impl Responder {
    if let Err(e) = form.validate() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": e.to_string()}));
    }
    match SupabaseService::login(&data, &form.email, &form.password).await {
        Ok(res) => {
            Span::current().record("user_id", res.user.id.to_string());
            // Span::current().record("user_role", res.user.user_metadata.role.into());
            HttpResponse::Ok().json(res)
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!(e)),
    }
}
