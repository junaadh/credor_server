//! Admin role guard and authorization utilities.
//!
//! This module provides security functions for enforcing administrative access control
//! throughout the application. It includes role checking, authorization guards, and
//! utility functions for protecting admin-only endpoints and operations.

use crate::{auth_middleware::AuthMiddleware, data::Role};
use actix_web::HttpResponse;

/// Checks if the authenticated user has administrative privileges.
///
/// This function examines the user's role from their JWT token to determine
/// if they have admin access. Used as a simple boolean check for conditional
/// logic and admin feature availability.
///
/// # Arguments
///
/// * `user` - Authenticated user context from JWT middleware
///
/// # Returns
///
/// * `true` - User has Admin role and can access administrative functions
/// * `false` - User has User role or no admin privileges
///
/// # Examples
///
/// ```rust
/// use crate::handlers::admin::guard::is_admin;
///
/// if is_admin(&user) {
///     println!("User has admin access");
/// } else {
///     println!("User has standard access");
/// }
/// ```
///
/// # Security Notes
///
/// - Role is verified from JWT token claims
/// - Does not perform additional database checks
/// - Should be used in conjunction with `admin_guard()` for endpoint protection
pub fn is_admin(user: &AuthMiddleware) -> bool {
    user.role == Role::Admin
}

/// Enforces administrative access control for protected endpoints.
///
/// This guard function provides a standardized way to protect admin-only endpoints
/// by checking the user's role and returning appropriate HTTP responses. It should
/// be called at the beginning of every admin endpoint handler.
///
/// # Arguments
///
/// * `user` - Authenticated user context from JWT middleware
///
/// # Returns
///
/// * `Ok(())` - User has admin privileges, allow endpoint access
/// * `Err(HttpResponse)` - User lacks admin privileges, return 403 Forbidden
///
/// # HTTP Response
///
/// On authorization failure, returns:
/// ```json
/// {
///   "error": "Admin access required"
/// }
/// ```
///
/// # Usage Pattern
///
/// All admin endpoints should follow this pattern:
/// ```rust
/// pub async fn admin_endpoint(user: AuthMiddleware) -> impl Responder {
///     if let Err(resp) = admin_guard(&user) {
///         return resp;  // Return 403 immediately
///     }
///     // Admin-only logic continues here...
/// }
/// ```
///
/// # Security Features
///
/// - Consistent 403 error response across all admin endpoints
/// - Prevents unauthorized access to sensitive operations
/// - Standardized error message for client applications
/// - Early return pattern prevents execution of admin logic
///
/// # Error Response Details
///
/// - **Status Code**: 403 Forbidden
/// - **Content-Type**: application/json
/// - **Body**: JSON object with error message
/// - **Logging**: Should be combined with audit logging for security monitoring
pub fn admin_guard(user: &AuthMiddleware) -> Result<(), HttpResponse> {
    if is_admin(user) {
        Ok(())
    } else {
        Err(HttpResponse::Forbidden().json(serde_json::json!({"error": "Admin access required"})))
    }
}
