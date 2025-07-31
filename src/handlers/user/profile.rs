//! User profile management endpoints.
//!
//! Provides handlers for updating and retrieving user profile information.

use crate::{
    AppState, SupabaseService, UpdateUserInput, admin::users::AdminUserProfile,
    auth_middleware::AuthMiddleware,
};
use actix_web::{HttpResponse, Responder, web};
use validator::Validate;

#[tracing::instrument(skip(user, app_state, payload), fields(user_id = %user.id, name = ?payload.name))]
pub async fn update_profile(
    user: AuthMiddleware,
    app_state: web::Data<AppState>,
    payload: web::Json<UpdateUserInput>,
) -> impl Responder {
    if let Err(e) = payload.validate() {
        return HttpResponse::BadRequest().json(serde_json::json!(e));
    }

    if let Err(e) = SupabaseService::update(&app_state, &user, payload.0).await
    {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({ "error": e.to_string() }));
    }

    HttpResponse::Ok().finish()
}

pub async fn get_profile(
    user: AuthMiddleware,
    app_state: web::Data<AppState>,
) -> impl Responder {
    let row = match sqlx::query!(
        r#"
        SELECT user_profiles.user_id, user_profiles.name, auth.users.email, user_profiles.age, user_profiles.gender
        FROM user_profiles
        JOIN auth.users ON user_profiles.user_id = auth.users.id
        WHERE user_profiles.user_id = $1
        "#,
        user.id
    )
    .fetch_one(app_state.db.as_ref())
    .await {
        Ok(r) => AdminUserProfile{ user_id: r.user_id, name: r.name, email: r.email.unwrap_or_default(), age: r.age, gender: r.gender },
        Err(e) => return HttpResponse::BadRequest().body(format!("failed to get user details: {e}")),
    };

    HttpResponse::Ok().json(serde_json::json!(row))
}
