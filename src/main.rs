//! Main entry point for the credor_server backend.
//!
//! Sets up Actix Web server, configures routes for user and admin APIs,
//! and initializes shared application state (database pool, Supabase keys).
//! Uses dotenv for config and launches the async runtime with comprehensive tracing.

use actix_web::{App, HttpServer, middleware::Logger, web};
use credor::{AppState, handlers, logging};
use dotenv::dotenv;

/// Main entry point. Configures and runs the Actix Web server.
///
/// - Loads environment variables from `.env`.
/// - Connects to the Postgres database.
/// - Initializes comprehensive tracing (stdout + database).
/// - Registers all user and admin routes with middleware.
/// - Launches the async server runtime.
#[tokio::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    // Initialize application state
    let app_state = AppState::new().await.expect("failed to init app_state");

    // Initialize unified structured logging (stdout + Postgres)
    logging::setup_tracing(app_state.db.clone());

    let server = HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(app_state.clone()))
            // Add comprehensive logging middleware
            // TracingLogger is already included in setup_tracing, so only keep Logger if desired
            .wrap(Logger::default())
            .service(
                web::scope("/api")
                    .route("/health", web::get().to(handlers::health::health_check))
                    .service(
                        web::scope("/admin")
                            // Authentication routes (no admin guard required)
                            .route(
                                "/register",
                                actix_web::web::post().to(handlers::admin::auth::register),
                            )
                            .route(
                                "/login",
                                actix_web::web::post().to(handlers::admin::auth::login),
                            )
                            // User management routes
                            .route(
                                "/users",
                                actix_web::web::get().to(handlers::admin::users::get_users),
                            )
                            // Scan job management routes
                            .route(
                                "/scans",
                                actix_web::web::get().to(handlers::admin::scans::get_scans),
                            )
                            .route(
                                "/scans/{job_id}",
                                actix_web::web::get().to(handlers::admin::scans::get_scan_details),
                            )
                            .route(
                                "/scans/{job_id}/status",
                                actix_web::web::patch()
                                    .to(handlers::admin::scans::patch_scan_status),
                            )
                            .route(
                                "/scans/{job_id}",
                                actix_web::web::delete().to(handlers::admin::scans::delete_scan),
                            )
                            // System monitoring routes
                            .route(
                                "/analytics",
                                actix_web::web::get()
                                    .to(handlers::admin::analytics::get_admin_analytics),
                            )
                            .route(
                                "/health",
                                actix_web::web::get().to(handlers::admin::health::get_admin_health),
                            )
                            .route(
                                "/logs",
                                actix_web::web::get().to(handlers::admin::logs::get_admin_logs),
                            ),
                    )
                    .service(
                        web::scope("/user")
                            // Authentication routes
                            .route("/register", web::post().to(handlers::user::register))
                            .route("/login", web::post().to(handlers::user::login))
                            .route("/delete", web::delete().to(handlers::user::delete_account))
                            // Profile management
                            .route("/profile", web::put().to(handlers::user::update_profile))
                            // Settings management
                            .route("/settings", web::get().to(handlers::user::get_settings))
                            .route("/settings", web::patch().to(handlers::user::patch_settings))
                            // Scan operations
                            .route("/scan", web::post().to(handlers::user::post_scan))
                            .route("/scan/history", web::get().to(handlers::user::get_history))
                            .route(
                                "/scan/{job_id}/results",
                                web::get().to(handlers::user::get_scan_results),
                            )
                            .route(
                                "/scan/{job_id}/status",
                                web::get().to(handlers::user::get_scan_status),
                            ),
                    ),
            )
    })
    .bind(("127.0.0.1", 8080))?
    .run();

    let srv_handle = server.handle();

    let server_task = tokio::spawn(server);

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::warn!("Shutdown signal received");
            // Gracefully stop the server
            srv_handle.stop(true).await;
        }
        res = server_task => {
            if let Err(e) = res {
                tracing::error!("Server task failed: {}", e);
            }
        }
    }

    Ok(())
}
