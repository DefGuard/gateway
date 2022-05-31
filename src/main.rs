use gateway::run_gateway_client;
use structopt::StructOpt;

mod error;
mod gateway;
mod utils;
mod wireguard;

#[macro_use]
extern crate log;

#[derive(StructOpt, Debug)]
#[structopt(name = "vpn-gateway", about = "DefGuard VPN gateway service")]
pub struct Config {
    #[structopt(
        long,
        short = "u",
        env = "DEFGUARD_USERSPACE",
        help = "Use userspace wireguard implementation, useful on systems without native wireguard support"
    )]
    userspace: bool,

    #[structopt(
        long,
        short = "g",
        env = "DEFGUARD_GRPC_URL",
        default_value = "https://localhost:50055",
        help = "DefGuard server GRPC endpoint URL"
    )]
    grpc_url: String,

    #[structopt(
        long,
        short = "p",
        env = "DEFGUARD_STATS_PERIOD",
        default_value = "60",
        help = "Defines how often (seconds) should interface statistics be sent to DefGuard server"
    )]
    stats_period: u64,
    #[structopt(
        long,
        short = "t",
        env = "DEFGUARD_TOKEN",
        help = "Token received on Defguard after completing network wizard"
    )]
    token: String,
}

pub const VERSION: Option<&'static str> = option_env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let config = Config::from_args();
    info!(
        "Starting wireguard gateway version {} with configuration: {:?}",
        VERSION.unwrap_or("0.0.0"),
        config
    );
    run_gateway_client(&config).await?;
    Ok(())
}
