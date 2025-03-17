use super::{FirewallError, FirewallRule, Policy};

#[derive(Debug, Clone)]
pub struct FirewallApi {
    pub ifname: String,
}

impl FirewallApi {
    #[must_use]
    pub fn new(ifname: &str) -> Self {
        Self {
            ifname: ifname.into(),
        }
    }
}

pub trait FirewallManagementApi {
    /// Sets up the firewall with the default policy and cleans up any existing rules
    fn setup(
        &self,
        default_policy: Option<Policy>,
        priority: Option<i32>,
    ) -> Result<(), FirewallError>;
    fn cleanup(&self) -> Result<(), FirewallError>;
    fn add_rule(&self, rule: FirewallRule) -> Result<(), FirewallError>;
    fn add_rules(&self, rules: Vec<FirewallRule>) -> Result<(), FirewallError>;
    fn set_firewall_default_policy(&mut self, policy: Policy) -> Result<(), FirewallError>;
    fn set_masquerade_status(&self, enabled: bool) -> Result<(), FirewallError>;
}
