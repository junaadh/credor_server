//! Supabase service abstraction for user authentication and account management.
//!
//! This module provides a high-level interface for interacting with Supabase Auth API,
//! handling user registration, login, and account deletion operations. It includes
//! comprehensive error handling with user-friendly messages while preserving debug
//! information for developers.
//!
//! # Examples
//!
//! ```rust,no_run
//! use crate::services::SupabaseService;
//! use crate::handlers::data::Role;
//!
//! // Register a new user
//! let result = SupabaseService::register(
//!     &app_data,
//!     "John Doe",
//!     "john@example.com",
//!     "secure_password",
//!     Role::User
//! ).await;
//!
//! // Login an existing user
//! let auth_response = SupabaseService::login(
//!     &app_data,
//!     "john@example.com",
//!     "secure_password"
//! ).await?;
//! ```

use actix_web::web;
use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    AppState, AuthMiddleware,
    admin::guard,
    data::{AuthError, AuthResponse, Role},
    handlers,
};

/// Error response structure returned by Supabase Auth API.
///
/// This struct represents the standardized error format used throughout
/// the application for authentication-related failures. It includes both
/// user-friendly messages and technical details for debugging.
#[derive(Debug, Deserialize, Serialize)]
pub struct SupabaseErrorResponse {
    /// HTTP status code indicating the type of error
    pub code: u16,
    /// Machine-readable error identifier for programmatic handling
    pub error_code: String,
    /// Human-readable error message with debugging information
    pub msg: String,
}

/// Service layer for Supabase authentication operations.
///
/// `SupabaseService` provides a clean abstraction over the Supabase Auth REST API,
/// handling the complexity of HTTP requests, response parsing, and error mapping.
/// All methods are async and return structured error types for consistent handling.
pub struct SupabaseService;

impl SupabaseService {
    /// Registers a new user account with Supabase Auth.
    ///
    /// Creates a new user account with the provided credentials and metadata.
    /// The user's role and name are stored in Supabase's user metadata for
    /// later retrieval during authentication.
    ///
    /// # Arguments
    ///
    /// * `data` - Application state containing Supabase configuration
    /// * `name` - Full name of the user to register
    /// * `email` - Email address for the new account (must be unique)
    /// * `password` - Password for the new account (subject to Supabase's password policy)
    /// * `role` - User role (User or Admin) for authorization purposes
    ///
    /// # Returns
    ///
    /// * `Ok(AuthResponse)` - Successful registration with user data and access tokens
    /// * `Err(AuthError)` - Registration failed due to validation, network, or Supabase errors
    ///
    /// # Errors
    ///
    /// * `AuthError::Request` - Network connectivity issues or request failures
    /// * `AuthError::Parse` - Invalid response format from Supabase
    /// * `AuthError::Supabase` - Supabase-specific errors (duplicate email, weak password, etc.)
    /// * `AuthError::Other` - Unexpected errors during processing
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use crate::services::SupabaseService;
    /// use crate::handlers::data::Role;
    ///
    /// let result = SupabaseService::register(
    ///     &app_data,
    ///     "Jane Smith",
    ///     "jane@example.com",
    ///     "SecurePassword123!",
    ///     Role::User
    /// ).await;
    ///
    /// match result {
    ///     Ok(auth_response) => println!("User registered: {}", auth_response.user.email),
    ///     Err(e) => eprintln!("Registration failed: {}", e),
    /// }
    /// ```
    pub async fn register(
        data: &web::Data<AppState>,
        name: &str,
        email: &str,
        password: &str,
        role: handlers::data::Role,
    ) -> Result<AuthResponse, AuthError> {
        let res = reqwest::Client::new()
            .post(format!("{}/auth/v1/signup", &data.supabase_url))
            .header("apikey", &data.supabase_anon_key)
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({
                "email": email,
                "password": password,
                "data": {
                    "name": name,
                    "role": role
                }
            }))
            .send()
            .await
            .map_err(|e| {
                AuthError::Request(format!(
                    "Unable to connect to authentication service. Please try again later. (Error: {e})"
                ))
            })?;

        let status = res.status();
        let body = res.text().await.map_err(|e| {
            AuthError::Request(format!(
                "Received an invalid response from authentication service. (Error: {e})"
            ))
        })?;

        if status.is_success() {
            let ok = serde_json::from_str(&body).map_err(|e| {
                AuthError::Parse(format!(
                    "Received an invalid response from authentication service. (Error: {e})"
                ))
            })?;
            Ok(ok)
        } else {
            match serde_json::from_str::<SupabaseErrorResponse>(&body) {
                Ok(s) => Err(AuthError::Supabase {
                    code: s.code,
                    error_code: s.error_code,
                    msg: s.msg,
                }),
                Err(e) => Err(AuthError::Other(format!(
                    "An unexpected error occurred while processing the authentication response. (Error: {e})"
                ))),
            }
        }
    }

    /// Authenticates a user with email and password.
    ///
    /// Attempts to log in a user using their email and password credentials.
    /// Returns authentication tokens and user information on success.
    ///
    /// # Arguments
    ///
    /// * `data` - Application state containing Supabase configuration
    /// * `email` - Email address of the user attempting to log in
    /// * `password` - Password for authentication
    ///
    /// # Returns
    ///
    /// * `Ok(AuthResponse)` - Successful login with access tokens and user data
    /// * `Err(SupabaseErrorResponse)` - Login failed due to invalid credentials, network issues, or server errors
    ///
    /// # Errors
    ///
    /// * Network errors (502) - Unable to connect to Supabase or invalid responses
    /// * Authentication errors (401) - Invalid email/password combination
    /// * Server errors (500) - Unexpected processing errors
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use crate::services::SupabaseService;
    ///
    /// let result = SupabaseService::login(
    ///     &app_data,
    ///     "user@example.com",
    ///     "password123"
    /// ).await;
    ///
    /// match result {
    ///     Ok(auth_response) => {
    ///         println!("Login successful for: {}", auth_response.user.email);
    ///         // Store access_token for subsequent requests
    ///     },
    ///     Err(e) => eprintln!("Login failed: {}", e.msg),
    /// }
    /// ```
    pub async fn login(
        data: &web::Data<AppState>,
        email: &str,
        password: &str,
    ) -> Result<handlers::data::AuthResponse, SupabaseErrorResponse> {
        let res = reqwest::Client::new()
            .post(format!(
                "{}/auth/v1/token?grant_type=password",
                &data.supabase_url
            ))
            .header("apikey", &data.supabase_anon_key)
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({
                "email": email,
                "password": password
            }))
            .send()
            .await
            .map_err(|e| SupabaseErrorResponse {
                code: 502,
                error_code: "bad_gateway".to_owned(),
                msg: format!(
                    "Unable to connect to authentication service. Please try again later. (Error: {e})"
                ),
            })?;

        let status = res.status();
        let body = res.text().await.map_err(|e| SupabaseErrorResponse {
            code: 502,
            error_code: "bad_gateway".to_owned(),
            msg: format!("Received an invalid response from authentication service. (Error: {e})"),
        })?;

        if status.is_success() {
            let res =
                serde_json::from_str::<AuthResponse>(&body).map_err(|e| SupabaseErrorResponse {
                    code: 502,
                    error_code: "bad_gateway".to_string(),
                    msg: format!(
                        "Received an invalid response from authentication service. (Error: {e})"
                    ),
                })?;
            Ok(res)
        } else {
            match serde_json::from_str::<SupabaseErrorResponse>(&body) {
                Ok(o) => Err(o),
                Err(e) => Err(SupabaseErrorResponse {
                    code: 500,
                    error_code: "internal_server_error".to_string(),
                    msg: format!(
                        "An unexpected error occurred while processing the authentication response. (Error: {e})"
                    ),
                }),
            }
        }
    }

    /// Deletes a user account from Supabase Auth.
    ///
    /// Permanently removes a user account from Supabase. This operation requires
    /// either admin privileges or the user attempting to delete their own account.
    /// Once deleted, the user account cannot be recovered.
    ///
    /// # Arguments
    ///
    /// * `data` - Application state containing Supabase configuration and service keys
    /// * `user` - Authenticated user context for authorization checking
    /// * `user_id` - UUID of the user account to delete
    ///
    /// # Returns
    ///
    /// * `Ok(())` - User account successfully deleted
    /// * `Err(SupabaseErrorResponse)` - Deletion failed due to authorization, network, or server errors
    ///
    /// # Authorization
    ///
    /// This method enforces the following authorization rules:
    /// * Admin users can delete any account
    /// * Regular users can only delete their own account
    /// * Attempting to delete another user's account without admin privileges returns a 403 error
    ///
    /// # Errors
    ///
    /// * `403 Forbidden` - User lacks permission to delete the specified account
    /// * `502 Bad Gateway` - Network connectivity issues or invalid responses from Supabase
    /// * `500 Internal Server Error` - Unexpected processing errors
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use crate::services::SupabaseService;
    /// use uuid::Uuid;
    ///
    /// // User deleting their own account
    /// let result = SupabaseService::delete(
    ///     &app_data,
    ///     &auth_middleware, // Contains user's auth context
    ///     user_id           // Same as auth_middleware.id
    /// ).await;
    ///
    /// match result {
    ///     Ok(()) => println!("Account deleted successfully"),
    ///     Err(e) => eprintln!("Delete failed: {}", e.msg),
    /// }
    /// ```
    ///
    /// # Security Notes
    ///
    /// * This operation uses Supabase's admin API and requires service key authentication
    /// * The deletion is permanent and cannot be undone
    /// * Consider implementing a soft delete mechanism for better data retention policies
    pub async fn delete(
        data: &web::Data<AppState>,
        user: &AuthMiddleware,
        user_id: Uuid,
    ) -> Result<(), SupabaseErrorResponse> {
        if !guard::is_admin(user) && user.id != user_id {
            return Err(SupabaseErrorResponse {
                code: 403,
                error_code: "forbidden".to_string(),
                msg: "You are not authorized to perform this action.".to_string(),
            });
        }

        let res = reqwest::Client::new()
            .delete(format!(
                "{}/auth/v1/admin/users/{}",
                data.supabase_url, user.id
            ))
            .header("apikey", &data.supabase_anon_key)
            .header(
                "Authorization",
                format!("Bearer {}", &data.supabase_service_key),
            )
            .send()
            .await
            .map_err(|e| SupabaseErrorResponse {
                code: 502,
                error_code: "bad_gateway".to_owned(),
                msg: format!(
                    "Unable to connect to authentication service. Please try again later. (Error: {e})"
                ),
            })?;

        let status = res.status();
        let body = res.text().await.map_err(|e| SupabaseErrorResponse {
            code: 502,
            error_code: "bad_gateway".to_owned(),
            msg: format!("Received an invalid response from authentication service. (Error: {e})"),
        })?;

        if status.is_success() {
            Ok(())
        } else {
            match serde_json::from_str::<SupabaseErrorResponse>(&body) {
                Ok(o) => Err(o),
                Err(e) => Err(SupabaseErrorResponse {
                    code: 500,
                    error_code: "internal_server_error".to_string(),
                    msg: format!(
                        "An unexpected error occurred while processing the delete request. (Error: {e})"
                    ),
                }),
            }
        }
    }

    pub async fn update(
        data: &web::Data<AppState>,
        user: &AuthMiddleware,
        input: UpdateUserInput,
    ) -> anyhow::Result<()> {
        // update user metadata in auth table
        if input.email.is_some()
            || input.password.is_some()
            || input.role.is_some()
            || input.name.is_some()
        {
            let client = Client::new();
            let mut metadata = serde_json::Map::new();

            if let Some(r) = &input.role {
                metadata.insert(String::from("role"), serde_json::to_value(r)?);
            }

            if let Some(n) = &input.name {
                metadata.insert(
                    String::from("name"),
                    serde_json::Value::String(n.to_owned()),
                );
            }

            let mut payload = serde_json::Map::new();
            if let Some(e) = &input.email {
                let key = String::from("email");
                let value = serde_json::Value::String(e.to_owned());

                metadata.insert(key.clone(), value.clone());
                payload.insert(key, value);
            }

            if let Some(p) = &input.password {
                payload.insert(
                    String::from("password"),
                    serde_json::Value::String(p.to_owned()),
                );
            }

            if !metadata.is_empty() {
                payload.insert(
                    String::from("user_metadata"),
                    serde_json::Value::Object(metadata),
                );
            }

            let res = client
                .put(format!(
                    "{}/auth/v1/admin/users/{}",
                    data.supabase_url, user.id
                ))
                .bearer_auth(&data.supabase_service_key)
                .header("apikey", &data.supabase_anon_key)
                .json(&payload)
                .send()
                .await?;

            if !res.status().is_success() {
                let body = res.text().await?;
                anyhow::bail!("Supabase auth update failed {body}");
            }
        }

        let mut tx = data.db.begin().await?;

        // Update user_profiles
        sqlx::query!(
            r#"
            UPDATE user_profiles
            SET
                name = COALESCE($1, name),
                age = COALESCE($2, age),
                gender = COALESCE($3, gender)
            WHERE user_id = $4
            "#,
            input.name,
            input.age,
            input.gender,
            user.id
        )
        .execute(&mut *tx)
        .await?;

        // Update user_settings
        sqlx::query!(
            r#"
            UPDATE user_settings
            SET
                email = COALESCE($1, email),
                scan_defaults = COALESCE($2, scan_defaults),
                theme = COALESCE($3, theme),
                notifications = COALESCE($4, notifications),
                language = COALESCE($5, language),
                timezone = COALESCE($6, timezone),
                updated_at = NOW()
            WHERE user_id = $7
            "#,
            input.email,
            input.scan_defaults,
            input.theme,
            input.notifications,
            input.language,
            input.timezone,
            user.id
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(())
    }
}

use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateUserInput {
    #[validate(email(message = "Invalid email"))]
    #[serde(default)]
    pub email: Option<String>,

    #[validate(length(min = 8, max = 64, message = "Password must be at least 8 characters"))]
    #[serde(default)]
    pub password: Option<String>,

    #[serde(default)]
    pub role: Option<Role>,

    #[validate(length(min = 1, message = "Name cannot be empty"))]
    #[serde(default)]
    pub name: Option<String>,

    #[serde(default)]
    pub age: Option<i32>,

    #[serde(default)]
    pub gender: Option<String>,

    #[serde(default)]
    pub scan_defaults: Option<serde_json::Value>,

    #[serde(default)]
    pub theme: Option<String>,

    #[serde(default)]
    pub notifications: Option<serde_json::Value>,

    #[serde(default)]
    pub language: Option<String>,

    #[serde(default)]
    pub timezone: Option<String>,
}
