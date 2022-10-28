use clap::Parser;
use defguard_gateway::{gateway::start, Config};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::parse();
    start(&config).await?;
    Ok(())
}
