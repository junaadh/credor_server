//! User profile management endpoints.
//!
//! Provides handlers for updating and retrieving user profile information.

use crate::{AppState, SupabaseService, UpdateUserInput, auth_middleware::AuthMiddleware};
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

    if let Err(e) = SupabaseService::update(&app_state, &user, payload.0).await {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": e.to_string() }));
    }

    HttpResponse::Ok().finish()
}
