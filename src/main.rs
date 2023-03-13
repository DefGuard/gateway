use clap::Parser;
use defguard_gateway::{gateway::start, Config};
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::parse();
    if config.version {
        println!("{}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    start(&config).await?;
    Ok(())
}
