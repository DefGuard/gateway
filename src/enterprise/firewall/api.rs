use std::net::IpAddr;

use super::{Address, Port, Protocol};

pub struct FirewallApi {
    pub ifname: String,
}

impl FirewallApi {
    pub fn new(ifname: &str, default_action: bool) -> Self {
        Self {
            ifname: ifname.into(),
        }
    }
}

pub trait FirewallManagementApi {
    fn setup(&self);
    fn clear(&self);
    fn set_access(
        &self,
        sources: Vec<Address>,
        destinations: Vec<Address>,
        destination_ports: Vec<Port>,
        protocols: Vec<Protocol>,
        allow: bool,
        id: u32,
    );
}
