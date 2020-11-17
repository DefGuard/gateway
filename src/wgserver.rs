use crate::wgservice::wire_guard_service_server::WireGuardService;
use crate::wgservice::{
    AssignAddrRequest, AssignAddrResponse, CreateInterfaceRequest, CreateInterfaceResponse,
    SetLinkRequest, SetLinkResponse, SetPeerRequest, SetPeerResponse, SetPrivateKeyRequest,
    SetPrivateKeyResponse,
};
use crate::wireguard::{
    assign_addr, create_interface, set_link_down, set_link_up, set_peer, set_private_key,
};
use std::thread;
use tonic::{Request, Response, Status};

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
