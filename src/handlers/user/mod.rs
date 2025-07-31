//! User handler module organization.
//!
//! Re-exports all user-related endpoint handlers for profile, scan, delete, and settings management.
pub mod auth;
pub mod bucket;
pub mod delete;
pub mod profile;
pub mod scan;
pub mod settings;

use actix_web::web;

pub use self::{
    auth::*,
    bucket::*,
    delete::*,
    profile::*,
    scan::{get_history, get_scan_results, get_scan_status, post_scan},
    settings::*,
};

/// Registers all user-related endpoints.
pub fn configure_user_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/user")
            // Authentication routes
            .route("/register", web::post().to(register))
            .route("/login", web::post().to(login))
            .route("/delete", web::delete().to(delete_account))
            // Profile management
            .route("/profile", web::put().to(update_profile))
            // Settings management
            .route("/settings", web::get().to(get_settings))
            .route("/settings", web::patch().to(patch_settings))
            // Scan operations
            .route("/scan", web::post().to(post_scan))
            .route("/scan/history", web::get().to(get_history))
            .route("/scan/{job_id}/results", web::get().to(get_scan_results))
            .route("/scan/{job_id}/status", web::get().to(get_scan_status))
            // Account management
            .route("/delete", web::delete().to(delete_account)),
    );
}
