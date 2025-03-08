use deepfake_server::server::DeepFakeServer;

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    #[allow(clippy::default_constructed_unit_structs)]
    DeepFakeServer::default().run()?.await
}
