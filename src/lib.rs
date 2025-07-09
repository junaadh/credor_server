//! Library entry point for the credor backend.
//!
//! Exports all core modules for use in integration tests and by the main binary.

pub mod auth_middleware;
pub mod db;
pub mod handlers;
pub mod models;
pub mod services;
pub mod telemetry;
// pub mod tracing;
// The following are directory modules, so use mod.rs, not .rs
pub mod scraper {
    pub mod client;
    pub use client::*;
}
pub mod detection {
    pub mod analyzer;
    pub use analyzer::*;
}

pub use auth_middleware::*;
pub use db::*;
pub use detection::*;
pub use handlers::*;
pub use models::AppState;
pub use models::*;
pub use scraper::*;
pub use services::*;
pub use telemetry::*;
// pub use tracing::*;
