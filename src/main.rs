use fern::colors::{Color, ColoredLevelConfig};
use tonic::transport::Server;
use wgserver::WGServer;
use wgservice::wire_guard_service_server::WireGuardServiceServer;

mod utils;
mod wgserver;
mod wgservice;
mod wireguard;

fn setup_logger() -> Result<(), fern::InitError> {
    let colors = ColoredLevelConfig::new()
    .trace(Color::BrightWhite)
    .debug(Color::BrightCyan)
    .info(Color::BrightGreen)
    .warn(Color::BrightYellow)
    .error(Color::BrightRed);
    fern::Dispatch::new()
        .format(move |out, message, record| {
            out.finish(format_args!(
                "[{}][{}][{}] {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f"),
                record.target(),
                colors.color(record.level()),
                message
            ))
        })
        .level(log::LevelFilter::Debug)
        .chain(std::io::stdout())
        .apply()?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    setup_logger()?;
    let addr = "[::]:50051".parse()?;
    log::debug!("Starting server on {}", addr);
    let wg = WGServer::default();
    log::info!("Server listening on {}", addr);
    Server::builder()
        .add_service(WireGuardServiceServer::new(wg))
        .serve(addr)
        .await?;
    Ok(())
}
