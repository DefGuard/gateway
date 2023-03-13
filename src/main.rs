use clap::Parser;
use defguard_gateway::{gateway::start, Config, VERSION};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::parse();
    if config.version {
        println!("{}", VERSION);
    } else {
        start(&config).await?;
    }
    Ok(())
}
