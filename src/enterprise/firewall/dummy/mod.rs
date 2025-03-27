use super::{
    api::{FirewallApi, FirewallManagementApi},
    FirewallError, FirewallRule, Policy, Protocol,
};
use crate::proto;

impl FirewallManagementApi for FirewallApi {
    fn setup(
        &mut self,
        _default_policy: Option<Policy>,
        _priority: Option<i32>,
    ) -> Result<(), FirewallError> {
        Ok(())
    }

    fn cleanup(&mut self) -> Result<(), FirewallError> {
        Ok(())
    }

    fn set_firewall_default_policy(&mut self, _policy: Policy) -> Result<(), FirewallError> {
        Ok(())
    }

    fn set_masquerade_status(&mut self, _enabled: bool) -> Result<(), FirewallError> {
        Ok(())
    }

    fn add_rules(&mut self, _rules: Vec<FirewallRule>) -> Result<(), FirewallError> {
        Ok(())
    }

    fn add_rule(&mut self, _rule: FirewallRule) -> Result<(), FirewallError> {
        Ok(())
    }

    fn begin(&mut self) -> Result<(), FirewallError> {
        Ok(())
    }

    fn rollback(&mut self) {}

    fn commit(&mut self) -> Result<(), FirewallError> {
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
