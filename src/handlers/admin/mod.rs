//! Admin handler module organization and route configuration.
//!
//! This module organizes all admin-related endpoint handlers and provides centralized
//! route configuration for administrative functions including user management, scan
//! moderation, system health monitoring, log access, and analytics dashboards.

pub mod analytics;
pub mod auth;
pub mod bucket;
pub mod guard;
pub mod health;
pub mod logs;
pub mod scans;
pub mod users;

/// Configures all administrative routes under the `/api/admin` scope.
///
/// This function registers all admin endpoints with their corresponding HTTP methods
/// and handler functions. All routes require admin authentication and are protected
/// by the admin guard middleware.
///
/// # Route Structure
/// ```
/// /api/admin/
/// ├── auth/
/// │   ├── POST /register    - Admin account registration
/// │   └── POST /login       - Admin authentication
/// ├── users/
/// │   └── GET /             - List all user profiles
/// ├── scans/
/// │   ├── GET /             - List scan jobs with pagination
/// │   ├── GET /{id}         - Get detailed scan job info
/// │   ├── PATCH /{id}/status - Update scan job status
/// │   └── DELETE /{id}      - Delete scan job and results
/// ├── analytics/
/// │   └── GET /             - System analytics and metrics
/// ├── health/
/// │   └── GET /             - System health and status
/// └── logs/
///     └── GET /             - System logs with filtering
/// ```
///
/// # Authentication
/// All routes except `/auth/login` and `/auth/register` require:
/// - Valid JWT token in Authorization header
/// - Admin role in token claims
/// - Active admin account status
///
/// # Error Responses
/// All admin routes can return:
/// - `401 Unauthorized`: Missing/invalid token
/// - `403 Forbidden`: Insufficient privileges
/// - `500 Internal Server Error`: System errors
///
/// # Usage
/// ```rust
/// use actix_web::web;
/// use crate::handlers::admin::configure_admin_routes;
///
/// let app = App::new()
///     .configure(configure_admin_routes);
/// ```
pub fn configure_admin_routes(cfg: &mut actix_web::web::ServiceConfig) {
    cfg.service(
        actix_web::web::scope("/api/admin")
            // Authentication routes (no admin guard required)
            .route("/register", actix_web::web::post().to(auth::register))
            .route("/login", actix_web::web::post().to(auth::login))
            // User management routes
            .route("/users", actix_web::web::get().to(users::get_users))
            // Scan job management routes
            .route("/scans", actix_web::web::get().to(scans::get_scans))
            .route(
                "/scans/{job_id}",
                actix_web::web::get().to(scans::get_scan_details),
            )
            .route(
                "/scans/{job_id}/status",
                actix_web::web::patch().to(scans::patch_scan_status),
            )
            .route(
                "/scans/{job_id}",
                actix_web::web::delete().to(scans::delete_scan),
            )
            // System monitoring routes
            .route(
                "/analytics",
                actix_web::web::get().to(analytics::get_admin_analytics),
            )
            .route(
                "/health",
                actix_web::web::get().to(health::get_admin_health),
            )
            .route("/logs", actix_web::web::get().to(logs::get_admin_logs)),
    );
}

/// Alternative configuration function for admin authentication routes only.
///
/// This function can be used when admin authentication needs to be configured
/// separately from other admin routes, such as when using different middleware
/// or security policies for authentication endpoints.
///
/// # Routes Configured
/// - `POST /register` - Admin account creation
/// - `POST /login` - Admin authentication
///
/// # Usage
/// ```rust
/// let app = App::new()
///     .service(
///         web::scope("/api/admin/auth")
///             .configure(configure_admin_auth)
///     );
/// ```
///
/// # Security Notes
/// - These routes typically don't require existing admin privileges
/// - Consider rate limiting for brute force protection
/// - May require additional validation (admin email allowlist)
pub fn configure_admin_auth(cfg: &mut actix_web::web::ServiceConfig) {
    cfg.route("/register", actix_web::web::post().to(auth::register))
        .route("/login", actix_web::web::post().to(auth::login));
}
