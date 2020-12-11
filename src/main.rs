use envconfig::Envconfig;

use tonic::transport::Server;
use wgserver::WGServer;
use wgservice::wire_guard_service_server::WireGuardServiceServer;

mod utils;
mod logger;
mod wgserver;
mod wgservice;
mod wireguard;
mod error;

#[derive(Debug, Envconfig)]
pub struct Config {
    #[envconfig(from = "ORI_USERSPACE", default = "false")]
    pub userspace: bool,

    #[envconfig(from = "ORI_PORT", default = "50051")]
    pub port: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // setup fern logging
    logger::setup()?;

    let config = Config::init_from_env()?;
    log::debug!("Starting server with config: {:?}", config);
    let addr = format!("[::]:{}", config.port).parse()?;
    let wg = WGServer::default();
    log::debug!("Started server with config: {:?}", config);
    log::info!("Server listening on {}", addr);
    Server::builder()
        .add_service(WireGuardServiceServer::new(wg))
        .serve(addr)
        .await?;
    Ok(())
}
