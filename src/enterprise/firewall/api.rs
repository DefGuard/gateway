use super::{FirewallConfig, FirewallError, FirewallRule, Policy};

#[derive(Debug, Clone)]
pub struct FirewallApi {
    pub ifname: String,
    pub default_policy: Policy,
    pub v4: bool,
}

impl FirewallApi {
    #[must_use]
    pub fn from_config(ifname: &str, config: &FirewallConfig) -> Self {
        Self {
            ifname: ifname.into(),
            default_policy: config.default_policy,
            v4: config.v4,
        }
    }

    pub fn config_changed(&self, config: &FirewallConfig) -> bool {
        self.default_policy != config.default_policy || self.v4 != config.v4
    }

    pub fn maybe_update_from_config(
        &mut self,
        config: &FirewallConfig,
    ) -> Result<bool, FirewallError> {
        debug!("Updating firewall configuration if it has changed");
        let changed = if self.default_policy != config.default_policy {
            self.default_policy = config.default_policy;
            true
        } else if self.v4 != config.v4 {
            self.v4 = config.v4;
            true
        } else {
            false
        };

        if changed {
            debug!(
                "Updated firewall configuration as it has changed, new configuration: {:?}",
                self
            );
        }

        Ok(changed)
    }
}

pub trait FirewallManagementApi {
    /// Sets up the firewall with the default policy and cleans up any existing rules
    fn setup(&self) -> Result<(), FirewallError>;
    fn cleanup(&self) -> Result<(), FirewallError>;
    fn add_rule(&self, rule: FirewallRule) -> Result<(), FirewallError>;
    fn apply_rules(&self, rules: Vec<FirewallRule>) -> Result<(), FirewallError>;
    fn set_firewall_default_policy(&mut self, policy: Policy) -> Result<(), FirewallError>;
    fn set_masquerade_status(&self, enabled: bool) -> Result<(), FirewallError>;
}
