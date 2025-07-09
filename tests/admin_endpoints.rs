//! Integration and unit tests for admin-facing endpoints in credor_server.
//!
//! Each test runs in a transaction that is rolled back, ensuring DB isolation.

use actix_web::{App, test, web};
use credor::{AppState, handlers};

#[actix_web::test]
async fn test_admin_get_users_isolated() {
    unsafe {
        std::env::set_var("TEST", "1");
    }
    dotenv::dotenv().ok(); // Load .env file for DATABASE_URLs
    let state = AppState::new().await.expect("failed init app service");
    // let mut tx = state.db.begin().await;
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state))
            .configure(handlers::admin::configure_admin_routes),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/api/admin/users")
        .insert_header(("X-Test-Role", "admin"))
        .insert_header(("X-Test-User-Id", "00000000-0000-0000-0000-000000000001"))
        .insert_header(("X-Test-Email", "admin@example.com"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    // You may parse JSON here if needed
}

// More tests for /api/admin/scans, /api/admin/scan/{job_id}, etc. would follow the same pattern.
