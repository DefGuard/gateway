use super::{
    api::{FirewallApi, FirewallManagementApi},
    FirewallError, FirewallRule, Policy, Protocol,
};
use crate::proto;

impl FirewallManagementApi for FirewallApi {
    fn setup(&self, _default_policy: Option<Policy>) -> Result<(), FirewallError> {
        Ok(())
    }

    fn cleanup(&self) -> Result<(), FirewallError> {
        Ok(())
    }

    fn set_firewall_default_policy(&mut self, _policy: Policy) -> Result<(), FirewallError> {
        Ok(())
    }

    fn set_masquerade_status(&self, _enabled: bool) -> Result<(), FirewallError> {
        Ok(())
    }

    fn add_rules(&self, _rules: Vec<FirewallRule>) -> Result<(), FirewallError> {
        Ok(())
    }

    fn add_rule(&self, _rule: FirewallRule) -> Result<(), FirewallError> {
        Ok(())
    }
}

impl Protocol {
    pub const fn from_proto(
        proto: proto::enterprise::firewall::Protocol,
    ) -> Result<Self, FirewallError> {
        match proto {
            _ => Ok(Self(proto as u8)),
        }
    }
}
