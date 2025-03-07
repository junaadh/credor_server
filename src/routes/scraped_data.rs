use actix_web::{HttpResponse, Responder, web};
use log::info;

use crate::data::ScrapedData;

pub async fn scraped_data(json: web::Json<ScrapedData>) -> impl Responder {
    info!("recieved: {json:#?}");

    HttpResponse::Ok().json(json)
}
