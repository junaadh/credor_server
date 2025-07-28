//! Authentication middleware for extracting user context from Supabase JWT or test headers.
//!
//! # Overview
//! This module provides [`AuthMiddleware`], an Actix Web extractor that injects a [`UserContext`] into handlers.
//! In production, it validates JWTs using Supabase, fetches user info, and loads extra profile fields from the local database.
//! In integration tests, if the headers `X-Test-Role`, `X-Test-User-Id`, and `X-Test-Email` are present, it injects a mock user context and bypasses real Supabase validation.
//!
//! # Usage
//! In handlers, add `user: AuthMiddleware` as an argument to receive the authenticated user's context.
//!
//! ## Test Mode
//! In integration tests, add the following headers to requests to inject a mock user:
//!
//! - `X-Test-Role`: The user's role (e.g., "admin" or "authenticated")
//! - `X-Test-User-Id`: The user's UUID
//! - `X-Test-Email`: The user's email address
//!
//! Example:
//! ```
//! use actix_web::test::TestRequest;
//!
//! let req = TestRequest::get()
//!     .uri("/api/some/protected/route")
//!     .insert_header(("X-Test-Role", "admin"))
//!     .insert_header(("X-Test-User-Id", "00000000-0000-0000-0000-000000000001"))
//!     .insert_header(("X-Test-Email", "admin@example.com"))
//!     .to_request();
//! ```
//!
//! # Errors
//! Returns 401 Unauthorized if the JWT is missing or invalid, or if Supabase validation fails.
//!
//! # See Also
//! - [`UserContext`]: The struct containing user info injected by this middleware.
//! - [`AppState`]: Application state required for DB and Supabase access.

use crate::{AppState, data::Role, handlers};
use actix_web::{FromRequest, HttpRequest};
use futures::future::BoxFuture;
use reqwest::Client;
use serde::Deserialize;
use std::{ops::Deref, str::FromStr};
use tracing::Span;
use uuid::Uuid;

/// Represents the authenticated user's context, extracted from Supabase JWT and user_profiles.
#[derive(Debug, Clone, Deserialize)]
pub struct UserContext {
    /// User's unique identifier (UUID as string)
    pub id: Uuid,
    /// User's email address
    pub email: String,
    /// User's role ("admin" or "authenticated")
    pub role: Role,
    /// User's display name
    pub name: Option<String>,
    /// User's age
    pub age: Option<i32>,
    /// User's gender
    pub gender: Option<String>,
}

/// Actix Web extractor for injecting [`UserContext`] into handlers.
///
/// Validates the Authorization header, fetches user info from Supabase,
/// and loads extra profile fields from the local DB.
#[derive(Debug, Clone)]
pub struct AuthMiddleware(pub UserContext);

impl Deref for AuthMiddleware {
    type Target = UserContext;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromRequest for AuthMiddleware {
    type Error = actix_web::Error;
    type Future = BoxFuture<'static, Result<Self, Self::Error>>;

    fn from_request(
        req: &HttpRequest,
        _payload: &mut actix_web::dev::Payload,
    ) -> Self::Future {
        // TEST SHORT-CIRCUIT: If running in tests and test headers are present, inject a mock user context
        if std::env::var("TEST").is_ok() && cfg!(debug_assertions) {
            if let (Some(role), Some(id), Some(email)) = (
                req.headers()
                    .get("X-Test-Role")
                    .and_then(|v| v.to_str().ok()),
                req.headers()
                    .get("X-Test-User-Id")
                    .and_then(|v| v.to_str().ok()),
                req.headers()
                    .get("X-Test-Email")
                    .and_then(|v| v.to_str().ok()),
            ) {
                tracing::debug!(
                    test_user_id = %id,
                    test_email = %email,
                    test_role = %role,
                    "Using test authentication headers"
                );

                let user_id = match Uuid::from_str(id) {
                    Ok(u) => u,
                    Err(e) => {
                        tracing::error!(
                            test_user_id = %id,
                            error = ?e,
                            "Invalid UUID in test headers"
                        );
                        return Box::pin(async move {
                            Err(actix_web::error::ErrorBadRequest(format!(
                                "Invalid UUID: {e}"
                            )))
                        });
                    }
                };

                let user = UserContext {
                    id: user_id,
                    email: email.to_string(),
                    role: Role::from(role),
                    name: Some("Test User".to_string()),
                    age: Some(24),
                    gender: Some("male".to_string()),
                };
                tracing::info!(
                    user_id = %user_id,
                    email = %email,
                    role = ?user.role,
                    "Test user authenticated"
                );
                return Box::pin(async move { Ok(AuthMiddleware(user)) });
            }
        }

        let req = req.clone();
        let app_data =
            req.app_data::<actix_web::web::Data<AppState>>().cloned();
        let auth_header = req.headers().get("Authorization").cloned();

        Box::pin(async move {
            let app_data = app_data.ok_or_else(|| {
                actix_web::error::ErrorUnauthorized("AppState missing")
            })?;

            tracing::debug!("Extracting auth token from request");

            // token extraction
            let token = auth_header
                .ok_or_else(|| {
                    tracing::warn!("No Authorization header present in request");
                    actix_web::error::ErrorUnauthorized("no authorization header")
                })?
                .to_str()
                .map_err(|e| {
                    tracing::warn!(error = ?e, "Invalid Authorization header format");
                    actix_web::error::ErrorUnauthorized(format!("invalid header format {e}"))
                })?
                .strip_prefix("Bearer ")
                .ok_or_else(|| {
                    tracing::warn!("Authorization header missing Bearer prefix");
                    actix_web::error::ErrorUnauthorized("invalid auth header")
                })?
                .to_string();

            tracing::debug!("Successfully extracted JWT token");

            // supabase auth
            tracing::debug!("Validating token with Supabase");

            let supabase_url = format!(
                "{}/auth/v1/user",
                app_data.supabase_url.trim_end_matches('/')
            );

            tracing::debug!(url = %supabase_url, "Calling Supabase Auth API");

            let res = Client::new()
                .get(supabase_url)
                .header("Authorization", format!("Bearer {token}"))
                .header("apikey", &app_data.supabase_anon_key)
                .send()
                .await
                .map_err(|e| {
                    tracing::error!(error = ?e, "Failed to connect to Supabase Auth API");
                    actix_web::error::ErrorBadRequest(format!("supabase auth failed: {e}"))
                })?;

            if !res.status().is_success() {
                let status = res.status();
                tracing::warn!(
                    status_code = %status.as_u16(),
                    "Supabase rejected token authentication"
                );
                return Err(actix_web::error::ErrorUnauthorized(
                    "Invalid Supabase token",
                ));
            }

            tracing::info!("Supabase validated token successfully");

            let user: handlers::data::User = res.json().await.map_err(|e| {
                tracing::error!(error = ?e, "Failed to parse Supabase user response");
                actix_web::error::ErrorUnauthorized(format!("Invalid Supabase user response: {e}"))
            })?;

            tracing::debug!(
                user_id = %user.id,
                email = %user.email,
                "Successfully retrieved user data from Supabase"
            );

            let mut ctx = UserContext {
                id: user.id,
                email: user.email,
                role: user.user_metadata.role,
                name: user.user_metadata.name,
                age: None,
                gender: None,
            };

            if ctx.role == Role::User {
                // Fetch extra profile fields from user_profiles
                tracing::debug!(user_id = %user.id, "Fetching additional profile data from database");

                let db = app_data.db.as_ref();
                let user_uuid = user.id;
                let row = sqlx::query!(
                    r#"SELECT name, age, gender FROM user_profiles WHERE user_id = $1"#,
                    user_uuid
                )
                .fetch_optional(db)
                .await
                .map_err(|e| {
                    tracing::error!(
                        user_id = %user_uuid,
                        error = ?e,
                        "Failed to fetch user profile from database"
                    );
                    actix_web::error::ErrorUnauthorized("Failed to fetch user profile")
                })?;

                if let Some(profile) = row {
                    tracing::debug!(
                        user_id = %user_uuid,
                        "Found user profile in database"
                    );
                    ctx.age = profile.age;
                    ctx.gender = profile.gender;
                } else {
                    tracing::debug!(
                        user_id = %user_uuid,
                        "No user profile found in database"
                    );
                }
            }

            tracing::info!(
                user_id = %ctx.id,
                email = %ctx.email,
                role = ?ctx.role,
                "User authenticated successfully"
            );

            Span::current().record("user_id", ctx.id.to_string());
            Ok(AuthMiddleware(ctx))
        })
    }
}
