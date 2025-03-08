use actix_web::{HttpResponse, Responder};

use crate::data::ScrapeCategories;

#[actix_web::get("/categories")]
pub async fn get_categories_handler() -> impl Responder {
    let vec = (0..ScrapeCategories::LEN)
        .map(ScrapeCategories::from)
        .collect::<Vec<_>>();

    HttpResponse::Ok().json(serde_json::json!({
        "data": vec
    }))
}
