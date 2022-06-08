use clap::Parser;
use env_logger::{init_from_env, Env, DEFAULT_FILTER_ENV};
use gateway::run_gateway_client;

mod error;
mod gateway;
mod utils;
mod wireguard;

#[macro_use]
extern crate log;

#[derive(Debug, Parser)]
#[clap(name = "vpn-gateway", about = "DefGuard VPN gateway service")]
pub struct Config {
    #[clap(
        long,
        short = 'u',
        env = "DEFGUARD_USERSPACE",
        help = "Use userspace wireguard implementation, useful on systems without native wireguard support"
    )]
    userspace: bool,

    #[clap(
        long,
        short = 'g',
        env = "DEFGUARD_GRPC_URL",
        default_value = "https://localhost:50055",
        help = "DefGuard server GRPC endpoint URL"
    )]
    grpc_url: String,

    #[clap(
        long,
        short = 'p',
        env = "DEFGUARD_STATS_PERIOD",
        default_value = "60",
        help = "Defines how often (seconds) should interface statistics be sent to DefGuard server"
    )]
    stats_period: u64,

    #[clap(
        long,
        short = 't',
        env = "DEFGUARD_TOKEN",
        help = "Token received on Defguard after completing network wizard"
    )]
    token: String,

    #[clap(
        long,
        short = 'i',
        env = "DEFGUARD_IFNAME",
        default_value = "wg0",
        help = "Interface name (e.g. wg0)"
    )]
    if_name: String,
}

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "info"));

    let config = Config::parse();
    info!(
        "Starting wireguard gateway version {} with configuration: {:?}",
        VERSION, config
    );
    run_gateway_client(&config).await?;
    Ok(())
}
