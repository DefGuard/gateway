use defguard_gateway::config::get_config;
use defguard_gateway::gateway::start;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = get_config()?;
    start(&config).await?;
    Ok(())
}
