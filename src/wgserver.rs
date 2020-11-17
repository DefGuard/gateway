use crate::wgservice::wire_guard_service_server::WireGuardService;
use crate::wgservice::{
    AssignAddrRequest, CreateInterfaceRequest, SetLinkRequest, SetPeerRequest,
    SetPrivateKeyRequest, Status,
};
use crate::wireguard::{
    assign_addr, create_interface, set_link_down, set_link_up, set_peer, set_private_key,
};
use std::thread;
use tonic::{Request, Response, Status as TonicStatus};

// defining a struct for our service
#[derive(Default)]
pub struct WGServer {}

#[tonic::async_trait]
impl WireGuardService for WGServer {
    async fn create_interface(
        &self,
        request: Request<CreateInterfaceRequest>,
    ) -> Result<Response<Status>, TonicStatus> {
        let request = request.into_inner();
        log::debug!("Creating interface {:?}", &request);
        let interface_name = request.name.clone();
        thread::spawn(move || {
            // FIXME: error handling
            create_interface(&interface_name);
        });
        log::info!("Created interface {:?}", &request);
        // FIXME: pass status from system call
        Ok(Response::new(Status {
            code: 0,
            message: String::new(),
        }))
    }

    async fn assign_addr(
        &self,
        request: Request<AssignAddrRequest>,
    ) -> Result<Response<Status>, TonicStatus> {
        let request = request.into_inner();
        log::debug!("Assigning address {:?}", &request);
        // FIXME: implement real error handling once service responses are implemented
        let status = assign_addr(&request.interface, &request.addr)?;
        log::info!("Assigned address {:?}", &request);
        Ok(Response::new(Status {
            code: status.code().unwrap(),
            message: String::new(),
        }))
    }

    async fn set_private_key(
        &self,
        request: Request<SetPrivateKeyRequest>,
    ) -> Result<Response<Status>, TonicStatus> {
        let request = request.into_inner();
        log::debug!("Setting prvate key on interface {}", &request.interface);
        let status = set_private_key(&request.interface, &request.key)?;
        log::info!("Set private key on interface {}", &request.interface);
        Ok(Response::new(Status {
            code: status.code().unwrap(),
            message: String::new(),
        }))
    }

    async fn set_link(
        &self,
        request: Request<SetLinkRequest>,
    ) -> Result<Response<Status>, TonicStatus> {
        let request = request.into_inner();
        log::debug!("Setting interface {:?}", &request);
        let status = match request.operation {
            // FIXME: can we use enum types defined in protos?
            0 => set_link_down(&request.interface)?,
            1 => set_link_up(&request.interface)?,
            operation => panic!("Undefined operation: {:?}", operation),
        };
        log::info!("Set interface {:?}", &request);
        Ok(Response::new(Status {
            code: status.code().unwrap(),
            message: String::new(),
        }))
    }

    async fn set_peer(
        &self,
        request: Request<SetPeerRequest>,
    ) -> Result<Response<Status>, TonicStatus> {
        let request = request.into_inner();
        log::debug!("Setting peer {:?}", &request);
        let status = set_peer(
            &request.interface,
            &request.pubkey,
            &request.allowed_ips,
            &request.endpoint,
        )?;
        log::info!("Set peer {:?}", &request);
        Ok(Response::new(Status {
            code: status.code().unwrap(),
            message: String::new(),
        }))
    }
}
