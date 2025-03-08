use actix_web::{HttpResponse, Responder};

use crate::data::Platform;

#[actix_web::get("/platforms")]
pub async fn get_platforms_handler() -> impl Responder {
    let vec = (0..Platform::LEN).map(Platform::from).collect::<Vec<_>>();

    HttpResponse::Ok().json(serde_json::json!({
        "data": vec
    }))
}
