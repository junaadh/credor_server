//! Integration and unit tests for user-facing endpoints in credor_server.
//!
//! Each test runs in a transaction that is rolled back, ensuring DB isolation.

use actix_web::{App, http::StatusCode, test, web};
use credor_server::{AppState, handlers};

/// Create a mock JWT auth header for a given role.
// fn mock_jwt_header(role: &str) -> (actix_web::http::header::HeaderName, String) {
//     (
//         actix_web::http::header::AUTHORIZATION,
//         format!("Bearer dummy.jwt.token.{role}"),
//     )
// }

#[actix_web::test]
async fn test_user_get_settings_requires_auth() {
    unsafe {
        std::env::set_var("TEST", "1");
    }
    dotenv::dotenv().ok();
    let state = AppState::new().await.expect("failed to create state");

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state))
            .configure(handlers::user::configure_user_routes),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/api/user/settings")
        .to_request(); // ⬅ no test headers

    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "Should fail without mock auth headers"
    );
}
