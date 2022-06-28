use clap::Parser;
use env_logger::{init_from_env, Env, DEFAULT_FILTER_ENV};
use wireguard_gateway::{gateway::start, Config, VERSION};

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
    start(&config).await?;
    Ok(())
}
