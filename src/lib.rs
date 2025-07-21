//! Library entry point for the credor backend.
//!
//! Exports all core modules for use in integration tests and by the main binary.

pub mod auth_middleware;
pub mod db;
pub mod handlers;
pub mod logging;
pub mod models;
pub mod scrapers;
pub mod services;
pub mod detection {
    pub mod analyzer;
    pub use analyzer::*;
}

pub use auth_middleware::*;
pub use db::*;
pub use detection::*;
pub use handlers::*;
pub use logging::*;
pub use models::AppState;
pub use models::*;
pub use services::*;
