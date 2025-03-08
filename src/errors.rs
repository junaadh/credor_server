use actix_web::{HttpResponse, Responder};

pub async fn error() -> impl Responder {
    HttpResponse::NotFound().json("oops! please contact admin support or check the url")
}
