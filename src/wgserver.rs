use wgservice::wire_guard_service_server::{WireGuardService, WireGuardServiceServer};
use wgservice::{CreateInterfaceRequest, CreateInterfaceResponse, AssignAddrRequest, AssignAddrResponse};
use tonic::{transport::Server, Request, Response, Status};

mod wgservice;

// defining a struct for our service
#[derive(Default)]
pub struct WGServer {}

fn create_interface(name: &String) -> i32 {
    0
}

#[tonic::async_trait]
impl WireGuardService for WGServer {
    async fn create_interface(&self, request: Request<CreateInterfaceRequest>) -> Result<Response<CreateInterfaceResponse>, Status> {
        // TODO: start service
        let status = create_interface(&request.get_ref().name);
        println!("Create interface status: {}", status);
        Ok(Response::new(CreateInterfaceResponse {
            status: status, 
        }))
    }

    async fn assign_addr(&self, request: Request<AssignAddrRequest>) -> Result<Response<AssignAddrResponse>, Status> {
        Ok(Response::new(AssignAddrResponse {
            status: 0,
        }))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // defining address for our service
    let addr = "[::1]:50051".parse().unwrap();
    // creating a service
    let wg = WGServer::default();
    println!("Server listening on {}", addr);
    // adding our service to our server.
    Server::builder()
        .add_service(WireGuardServiceServer::new(wg))
        .serve(addr)
        .await?;
    Ok(())
}
