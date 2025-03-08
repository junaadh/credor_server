use actix_web::{App, HttpServer, dev::Server, middleware, web};
use reqwest::Client;

use crate::{errors, routes};

pub struct DeepFakeServer;

impl Default for DeepFakeServer {
    fn default() -> Self {
        // TODO: more robust log handling
        env_logger::init();
        Self
    }
}

impl DeepFakeServer {
    pub fn run(&self /* ,listener: TcpListener */) -> Result<Server, std::io::Error> {
        Ok(HttpServer::new(|| {
            App::new()
                // TODO: client error handling
                .app_data(web::Data::new(Client::new()))
                .wrap(middleware::Logger::default())
                .service(
                    web::scope("api/v1")
                        .service(routes::health_handler)
                        .service(routes::scraped_data_handler)
                        .service(routes::start_scrape_handler)
                        .service(routes::get_categories_handler)
                        .service(routes::get_platforms_handler),
                )
                .default_service(web::to(errors::error))
        })
        // TODO: allow for selection of host and port uisng coonfig file
        .bind("0.0.0.0:6996")?
        .run())
    }
}
