use crate::{
    AppState, AuthMiddleware, SupabaseService, admin::guard::admin_guard,
};
use actix_web::{HttpResponse, web};
use serde::Deserialize;
use tracing::info;
use uuid::Uuid;

#[derive(Deserialize, Debug)]
pub struct UserQuery {
    user_id: Uuid,
}

pub async fn handle_retrieve(
    data: actix_web::web::Data<AppState>,
    user: AuthMiddleware,
    web::Query(user_id): web::Query<UserQuery>,
) -> HttpResponse {
    if let Err(resp) = admin_guard(&user) {
        return resp;
    }

    info!("{user_id:?}");

    let key = match sqlx::query!(
        "SELECT key FROM encodings WHERE user_id = $1",
        user_id.user_id
    )
    .fetch_optional(data.db.as_ref())
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => return HttpResponse::NotFound().body("Encoding not found"),
        Err(e) => {
            return HttpResponse::InternalServerError().body(e.to_string());
        }
    }
    .key;

    info!("{key}");

    match SupabaseService::retrieve(&data, &key).await {
        Ok(o) => HttpResponse::Ok().content_type(o.mime).body(o.bytes),
        Err(e) => e.error_response(),
    }
}
