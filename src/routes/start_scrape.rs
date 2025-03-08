use actix_web::{HttpResponse, Responder, web};

use crate::data::ScrapeRequestPayload;

#[actix_web::post("/scrape")]
pub async fn start_scrape_handler(json: web::Json<ScrapeRequestPayload>) -> impl Responder {
    log::info!("{json:#?}");
    HttpResponse::Ok().json(json)
}
