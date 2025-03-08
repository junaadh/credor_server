use actix_web::web;
use log::warn;
use reqwest::Client;

pub async fn is_link_alive(client: &web::Data<Client>, url: &str) -> bool {
    match client.get(url).send().await {
        Ok(resp) => resp.status().is_success(),
        Err(e) => {
            warn!("reqwest error occured: {e:?}");
            false
        }
    }
}
