use crate::data::ScrapedData;
use actix_web::{HttpResponse, Responder, post, web};
use log::info;
use reqwest::Client;

#[post("/scraped-data")]
pub async fn scraped_data_handler(
    _client: web::Data<Client>,
    json: web::Json<ScrapedData>,
) -> impl Responder {
    info!("recieved: {json:#?}");

    HttpResponse::Ok().json(json)
}
