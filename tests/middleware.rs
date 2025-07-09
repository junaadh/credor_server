//! Middleware and auth tests for credor_server.
//!
//! Tests AuthMiddleware and AdminGuard behavior, including JWT extraction and role enforcement.

use actix_web::{App, test, web};
use credor::{AppState, auth_middleware, data::Role, handlers};
use uuid::Uuid;

#[actix_web::test]
async fn test_auth_middleware_rejects_missing_jwt() {
    dotenv::dotenv().ok();
    let app_state = AppState::new().await.expect("failed to init appstate");
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(app_state))
            .configure(handlers::user::configure_user_routes),
    )
    .await;
    let req = test::TestRequest::get()
        .uri("/api/user/settings")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
}

#[actix_web::test]
async fn test_admin_guard_forbids_non_admin() {
    unsafe {
        std::env::set_var("TEST", "1");
    }
    let user_ctx = auth_middleware::AuthMiddleware(auth_middleware::UserContext {
        id: Uuid::new_v4(),
        email: "user@example.com".to_string(),
        role: Role::User,
        name: Some("Test User".to_string()),
        age: Some(30),
        gender: Some("male".to_string()),
    });
    let result = handlers::admin::guard::admin_guard(&user_ctx);
    assert!(result.is_err());
    if let Err(resp) = result {
        assert_eq!(resp.status(), 403);
    }
}

// More tests for JWT extraction, admin access, and error cases can be added here.
