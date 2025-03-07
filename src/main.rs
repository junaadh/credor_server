use deepfake_server::server::DeepFakeServer;

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    DeepFakeServer::default().run()?.await
}
