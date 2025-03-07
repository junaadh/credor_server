use actix_web::{HttpResponse, Responder, http::StatusCode};

pub async fn health() -> impl Responder {
    HttpResponse::Ok()
}
