use tonic::{Request, Response, Status as TonicStatus};
use structopt::StructOpt;
use std::thread;
use crate::{error::OriWireGuardError, wgservice::wire_guard_service_server::WireGuardService};
use crate::wgservice::{
    AssignAddrRequest, CreateInterfaceRequest, InterfaceStatsRequest, InterfaceStatsResponse,
    SetLinkRequest, SetPeerRequest, SetPrivateKeyRequest, Status,
};
use crate::wireguard::{
    assign_addr, create_interface, create_interface_userspace, interface_stats, set_link_down, set_link_up, set_peer,
    set_private_key,
};
use crate::utils::parse_wg_stats;
use crate::Config;


#[derive(Default)]
pub struct WGServer {}

impl From<OriWireGuardError> for TonicStatus {
    fn from(err: OriWireGuardError) -> Self {
        match err {
            OriWireGuardError::CommandExecutionFailed {..} => TonicStatus::unknown("Command execution failed"),
            OriWireGuardError::CommandExecutionError {stderr} => TonicStatus::unknown(format!("Command returned error: {}", stderr))
        }
    }
}

#[tonic::async_trait]
impl WireGuardService for WGServer {
    /// Handles wireguard interface creation.
    /// 
    /// Uses unserspace wireguard implementation if ORI_USERSPACE 
    /// environment variable is set to true.
    async fn create_interface(
        &self,
        request: Request<CreateInterfaceRequest>,
    ) -> Result<Response<Status>, TonicStatus> {
        let request = request.into_inner();
        // FIXME: pass config from main
        if Config::from_args().userspace {
            log::debug!("Creating userspace interface {:?}", &request);
            let ifname = request.name.clone();
            thread::spawn(move || {
                create_interface_userspace(&ifname);
            });
            log::info!("Created interface {:?}", &request);
            return Ok(Response::new(Status {
                code: 0,
                message: String::new(),
            }))
        }
        log::debug!("Creating interface {:?}", &request);
        create_interface(&request.name)?;
        log::info!("Created interface {:?}", &request);
        Ok(Response::new(Status {
            code: 0,
            message: String::new(),
        }))
    }

    /// Handles interface address assignment.
    async fn assign_addr(
        &self,
        request: Request<AssignAddrRequest>,
    ) -> Result<Response<Status>, TonicStatus> {
        let request = request.into_inner();
        log::debug!("Assigning address {:?}", &request);
        assign_addr(&request.interface, &request.addr)?;
        log::info!("Assigned address {:?}", &request);
        Ok(Response::new(Status {
            code: 0,
            message: String::new(),
        }))
    }

    /// Handles interface private key assignment.
    async fn set_private_key(
        &self,
        request: Request<SetPrivateKeyRequest>,
    ) -> Result<Response<Status>, TonicStatus> {
        let request = request.into_inner();
        log::debug!("Setting prvate key on interface {}", &request.interface);
        set_private_key(&request.interface, &request.key)?;
        log::info!("Set private key on interface {}", &request.interface);
        Ok(Response::new(Status {
            code: 0,
            message: String::new(),
        }))
    }

    /// Handles interface up / down operations.
    async fn set_link(
        &self,
        request: Request<SetLinkRequest>,
    ) -> Result<Response<Status>, TonicStatus> {
        let request = request.into_inner();
        log::debug!("Setting interface {:?}", &request);
        match request.operation {
            // FIXME: can we use enum types defined in protos?
            0 => set_link_down(&request.interface),
            1 => set_link_up(&request.interface),
            op => {
                return Ok(Response::new(Status {
                    code: 10,
                    message: String::from(format!("Unrecognized operation code: {}", op)),
                }))
            }
        }?;
        log::info!("Set interface {:?}", &request);
        Ok(Response::new(Status {
            code: 0,
            message: String::new(),
        }))
    }

    /// Handles peer assignment.
    async fn set_peer(
        &self,
        request: Request<SetPeerRequest>,
    ) -> Result<Response<Status>, TonicStatus> {
        let request = request.into_inner();
        log::debug!("Setting peer {:?}", &request);
        set_peer(
            &request.interface,
            &request.pubkey,
            &request.allowed_ips,
            &request.endpoint,
        )?;
        log::info!("Set peer {:?}", &request);
        Ok(Response::new(Status {
            code: 0,
            message: String::new(),
        }))
    }

    /// Handles interface statistics.
    async fn interface_stats(
        &self,
        request: Request<InterfaceStatsRequest>,
    ) -> Result<Response<InterfaceStatsResponse>, TonicStatus> {
        let request = request.into_inner();
        log::debug!("Displaying interface stats {:?}", &request);
        let output = interface_stats(&request.interface)?;
        log::info!("Displayed interface stats {:?}", &request);
        Ok(Response::new(InterfaceStatsResponse {
            code: 0,
            stats: parse_wg_stats(&output),
            message: String::new(),
        }))
    }
}
