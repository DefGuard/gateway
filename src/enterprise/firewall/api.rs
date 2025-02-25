use std::net::IpAddr;

use super::{Address, FirewallError, FirewallRule, Policy, Port, Protocol};

pub struct FirewallApi {
    pub ifname: String,
}

impl FirewallApi {
    pub fn new(ifname: &str) -> Self {
        Self {
            ifname: ifname.into(),
        }
    }
}

pub trait FirewallManagementApi {
    fn setup(&self) -> Result<(), FirewallError>;
    fn clear(&self) -> Result<(), FirewallError>;
    fn apply_rule(&self, rule: FirewallRule) -> Result<(), FirewallError>;
    fn set_default_policy(&self, policy: Policy) -> Result<(), FirewallError>;
}
