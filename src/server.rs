use crate::routes;
use actix_web::{App, HttpServer, dev::Server, middleware, web};
use reqwest::Client;

pub struct DeepFakeServer;

impl Default for DeepFakeServer {
    fn default() -> Self {
        // more robust log handling
        env_logger::init();
        Self
    }
}

impl DeepFakeServer {
    pub fn run(&self /* ,listener: TcpListener */) -> Result<Server, std::io::Error> {
        Ok(HttpServer::new(|| {
            App::new()
                // TODO: client error handling
                .app_data(Client::new())
                .wrap(middleware::Logger::default())
                .service(
                    web::scope("api/v1")
                        .route("/health", web::get().to(routes::health))
                        .route("/scraped-data", web::post().to(routes::scraped_data)),
                )
        })
        // TODO: allow for selection of host and port uisng coonfig file
        .bind("0.0.0.0:6996")?
        .run())
    }
}
