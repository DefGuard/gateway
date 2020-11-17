use tonic::{transport::Server};
use wgservice::wire_guard_service_server::WireGuardServiceServer;
use wgserver::WGServer;

mod wireguard;
mod wgservice;
mod wgserver;
mod utils;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::]:50051".parse()?;
    let wg = WGServer::default();
    println!("Server listening on {}", addr);
    Server::builder()
        .add_service(WireGuardServiceServer::new(wg))
        .serve(addr)
        .await?;
    Ok(())
}
