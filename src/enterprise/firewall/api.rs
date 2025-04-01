#[cfg(target_os = "linux")]
use nftnl::Batch;

use super::{FirewallError, FirewallRule, Policy};

pub struct FirewallApi {
    pub ifname: String,
    #[cfg(target_os = "linux")]
    #[allow(dead_code)]
    pub(crate) batch: Option<Batch>,
}

impl FirewallApi {
    #[must_use]
    pub fn new(ifname: &str) -> Self {
        Self {
            ifname: ifname.into(),
            #[cfg(target_os = "linux")]
            batch: None,
        }
    }
}

pub trait FirewallManagementApi {
    /// Sets up the firewall with the default policy and cleans up any existing rules
    fn setup(
        &mut self,
        default_policy: Option<Policy>,
        priority: Option<i32>,
    ) -> Result<(), FirewallError>;
    fn cleanup(&mut self) -> Result<(), FirewallError>;
    fn add_rule(&mut self, rule: FirewallRule) -> Result<(), FirewallError>;
    fn add_rules(&mut self, rules: Vec<FirewallRule>) -> Result<(), FirewallError>;
    fn set_firewall_default_policy(&mut self, policy: Policy) -> Result<(), FirewallError>;
    fn set_masquerade_status(&mut self, enabled: bool) -> Result<(), FirewallError>;
    fn begin(&mut self) -> Result<(), FirewallError>;
    fn commit(&mut self) -> Result<(), FirewallError>;
    fn rollback(&mut self);
}
