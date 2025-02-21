use std::net::IpAddr;

use super::{Address, FirewallRule, Port, Protocol};

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
    fn setup(&self);
    fn clear(&self);
    fn apply_rule(&self, rule: FirewallRule);
    fn set_default_action(&self, allow: bool);
}
