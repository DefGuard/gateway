use clap::Parser;
use env_logger::{init_from_env, Env, DEFAULT_FILTER_ENV};
use wireguard_gateway::{gateway::run_gateway_client, Config, VERSION};

#[macro_use]
extern crate log;

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
