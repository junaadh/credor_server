use std::env;

use actix_web::{
    HttpRequest, HttpResponse,
    http::header::CONTENT_TYPE,
    web::{self, Data},
};
use tracing::info;

use crate::{AppState, AuthMiddleware, SupabaseService};

pub async fn handle_upload(
    data: Data<AppState>,
    user: AuthMiddleware,
    req: HttpRequest,
    body: web::Bytes,
) -> HttpResponse {
    let content_type = req
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|mime| mime.to_str().ok())
        .unwrap_or("");

    if !content_type.starts_with("image/") {
        return HttpResponse::UnsupportedMediaType()
            .body("Only image/* types allowed");
    }

    if let Some(kind) = infer::get(&body) {
        if !kind.mime_type().starts_with("image/") {
            return HttpResponse::UnsupportedMediaType().body(format!(
                "Detected non-image content: {}",
                kind.mime_type()
            ));
        }

        let ext = kind.extension();

        match SupabaseService::upload(&data, &user, ext, &body).await {
            Ok(r) => {
                match sqlx::query!(
                    "INSERT INTO encodings (id, user_id, key) VALUES ($1, $2, $3) ON CONFLICT (id) DO UPDATE SET user_id = EXCLUDED.user_id, key = EXCLUDED.key",
                    r.id,
                    user.id,
                    r.key,
                ).execute(data.db.as_ref()).await {
                    Ok(_) => {},
                    Err(e) => return HttpResponse::InternalServerError().body(e.to_string())
                }

                tokio::spawn(async move {
                    let ai = env::var("AI_SERVER_IP")
                        .expect("failed to get ai server ip");
                    let user_id = user.id;
                    if let Err(e) = reqwest::Client::new()
                        .get(format!("{ai}/encode"))
                        .query(&[("user_id", user_id)])
                        .send()
                        .await
                    {
                        info!("failed to start profile encoding: {e}");
                    }
                });

                HttpResponse::Ok().json(serde_json::json!(r))
            }
            Err(e) => e.error_response(),
        }
    } else {
        HttpResponse::BadRequest().body("Could not detect image type")
    }
}

pub async fn handle_retrieve(
    data: Data<AppState>,
    user: AuthMiddleware,
) -> HttpResponse {
    let key = match sqlx::query!(
        "SELECT key FROM encodings WHERE user_id = $1",
        user.id
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
