use actix_web::{HttpResponse, Responder, get};

#[get("/health")]
pub async fn health_handler() -> impl Responder {
    HttpResponse::Ok()
}
