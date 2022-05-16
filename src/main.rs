use gateway::run_gateway_client;
use structopt::StructOpt;

mod error;
mod gateway;
mod utils;
mod wireguard;

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
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let config = Config::from_args();
    log::info!(
        "Starting wireguard gateway with configuration: {:?}",
        config
    );
    run_gateway_client(&config).await?;
    Ok(())
}
