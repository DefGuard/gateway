use std::thread;
use tonic::{transport::Server, Request, Response, Status};
mod wgservice;
use wgservice::wire_guard_service_server::{WireGuardService, WireGuardServiceServer};
use wgservice::{
    AssignAddrRequest, AssignAddrResponse, CreateInterfaceRequest, CreateInterfaceResponse,
    SetLinkRequest, SetLinkResponse, SetPeerRequest, SetPeerResponse, SetPrivateKeyRequest,
    SetPrivateKeyResponse,
};
mod wg;
use wg::create_interface;
mod utils;
use utils::{assign_addr, set_link_down, set_link_up, set_private_key, set_peer};

// defining a struct for our service
#[derive(Default)]
pub struct WGServer {}

#[tonic::async_trait]
impl WireGuardService for WGServer {
    async fn create_interface(
        &self,
        request: Request<CreateInterfaceRequest>,
    ) -> Result<Response<CreateInterfaceResponse>, Status> {
        let interface_name = request.get_ref().name.clone();
        thread::spawn(move || {
            // FIXME: error handling
            create_interface(&interface_name);
        });
        println!("Created interface {}", request.get_ref().name);
        // FIXME: pass status from system call
        Ok(Response::new(CreateInterfaceResponse { status: 0 }))
    }

    async fn assign_addr(
        &self,
        request: Request<AssignAddrRequest>,
    ) -> Result<Response<AssignAddrResponse>, Status> {
        let unpacked = request.get_ref();
        let status = assign_addr(&unpacked.interface, &unpacked.addr)?;
        println!("{:?}", status);
        Ok(Response::new(AssignAddrResponse {
            status: status.code().unwrap(),
        }))
    }

    async fn set_private_key(
        &self,
        request: Request<SetPrivateKeyRequest>,
    ) -> Result<Response<SetPrivateKeyResponse>, Status> {
        let unpacked = request.get_ref();
        let status = set_private_key(&unpacked.interface, &unpacked.key)?;
        println!("{:?}", status);
        Ok(Response::new(SetPrivateKeyResponse {
            status: status.code().unwrap(),
        }))
    }

    async fn set_link(
        &self,
        request: Request<SetLinkRequest>,
    ) -> Result<Response<SetLinkResponse>, Status> {
        let unpacked = request.get_ref();
        let status = match unpacked.operation {
            // FIXME: can we use enum types defined in protos?
            0 => set_link_up(&unpacked.interface)?,
            1 => set_link_down(&unpacked.interface)?,
            operation => panic!("Undefined operation: {:?}", operation),
        };
        println!("{:?}", status);
        Ok(Response::new(SetLinkResponse {
            status: status.code().unwrap(),
        }))
    }
    
    async fn set_peer(
        &self,
        request: Request<SetPeerRequest>,
    ) -> Result<Response<SetPeerResponse>, Status> {
        let unpacked = request.get_ref();
        let status = set_peer(
            &unpacked.interface,
            &unpacked.pubkey,
            &unpacked.allowed_ips,
            &unpacked.endpoint,
        )?;
        println!("{:?}", status);
        Ok(Response::new(SetPeerResponse {
            status: status.code().unwrap(),
        }))
    }
}

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
