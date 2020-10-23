use std::thread;
use tonic::{transport::Server, Request, Response, Status};
mod wgservice;
use wgservice::wire_guard_service_server::{WireGuardService, WireGuardServiceServer};
use wgservice::{CreateInterfaceRequest, CreateInterfaceResponse, AssignAddrRequest, AssignAddrResponse};
mod wg;
use wg::create_interface;

// defining a struct for our service
#[derive(Default)]
pub struct WGServer {}

async fn assign_addr(interface: String, addr: String) -> i32 {
    0
}

#[tonic::async_trait]
impl WireGuardService for WGServer {
    async fn create_interface(&self, request: Request<CreateInterfaceRequest>) -> Result<Response<CreateInterfaceResponse>, Status> {
        let interface_name = request.get_ref().name.clone();
        thread::spawn(move || {
            // FIXME: error handling
            create_interface(&interface_name);
        });
        println!("Created interface {}", request.get_ref().name);
        Ok(Response::new(CreateInterfaceResponse {
            status: 0, 
        }))
    }

    async fn assign_addr(&self, request: Request<AssignAddrRequest>) -> Result<Response<AssignAddrResponse>, Status> {
        let unpacked = request.get_ref(); 
        // FIXME: get rid of the clones
        let status = assign_addr(unpacked.clone().interface , unpacked.clone().addr).await;
        println!("Assign addr status: {}", status);
        Ok(Response::new(AssignAddrResponse {
            status: status, 
        }))
   }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse().unwrap();
    let wg = WGServer::default();
    println!("Server listening on {}", addr);
    Server::builder()
        .add_service(WireGuardServiceServer::new(wg))
        .serve(addr)
        .await?;
    Ok(())
}
