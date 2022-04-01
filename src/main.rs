use structopt::StructOpt;
use tonic::transport::Server;
use wgserver::WGServer;
use wgservice::wire_guard_service_server::WireGuardServiceServer;

mod error;
mod utils;
mod wgserver;
mod wgservice;
mod wireguard;

#[derive(StructOpt, Debug)]
#[structopt(name = "wireguard-gateway")]
pub struct Config {
    #[structopt(long, short = "u", env = "DEFGUARD_USERSPACE")]
    userspace: bool,

    #[structopt(long, short = "p", env = "DEFGUARD_PORT", default_value = "50051")]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let config = Config::from_args();
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
