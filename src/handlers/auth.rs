use actix_web::{HttpResponse, web};
use serde::Deserialize;
use validator::Validate;

use crate::AppState;

#[derive(Debug, Deserialize, Validate)]
pub struct ValidateEmailRequest {
    #[validate(email)]
    pub email: String,
}

#[derive(Deserialize)]
struct SupabaseUserList {
    users: Vec<SupabaseUser>,
}

#[derive(Deserialize)]
struct SupabaseUser {
    email: String,
}

pub async fn validate_unused_email(
    data: web::Data<AppState>,
    payload: web::Query<ValidateEmailRequest>,
) -> HttpResponse {
    if let Err(e) = payload.validate() {
        return HttpResponse::BadRequest().json(serde_json::json!(e));
    }

    let res = match reqwest::Client::new()
        .get(format!("{}/auth/v1/admin/users", &data.supabase_url))
        .header(
            "Authorization",
            format!("Bearer {}", &data.supabase_service_key),
        )
        .header("apikey", &data.supabase_service_key)
        .send()
        .await
        .map_err(|e| {
            HttpResponse::InternalServerError()
                .body(format!("Failed to contact Supabase: {e}"))
        }) {
        Ok(r) => r,
        Err(e) => return e,
    };

    let user_list = match res.json::<SupabaseUserList>().await {
        Ok(l) => l,
        Err(e) => {
            return HttpResponse::InternalServerError()
                .body(format!("failed to parse supabase response: {e}"));
        }
    };

    let taken = user_list.users.iter().any(|x| x.email == payload.email);

    HttpResponse::Ok().json(serde_json::json!({ "taken": taken }))
}
