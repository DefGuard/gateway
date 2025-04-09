use pf::{init_firewall, set_default_policy, DEFGUARD_ANCHOR};
use pfctl::{AnchorChange, Transaction};

use super::{
    api::{FirewallApi, FirewallManagementApi},
    FirewallError, FirewallRule, Policy, Protocol,
};
use crate::proto;

pub mod pf;

#[derive(Default)]
pub(crate) struct PfRules {
    pub filter_rules: Vec<pfctl::FilterRule>,
}

impl PfRules {
    pub fn add_filter_rule(&mut self, rule: pfctl::FilterRule) {
        self.filter_rules.push(rule);
    }
}

impl From<PfRules> for AnchorChange {
    fn from(rules: PfRules) -> Self {
        let mut change = AnchorChange::new();
        change.set_filter_rules(rules.filter_rules);
        change
    }
}

impl FirewallManagementApi for FirewallApi {
    fn setup(
        &mut self,
        default_policy: Option<Policy>,
        _priority: Option<i32>,
    ) -> Result<(), FirewallError> {
        if let Some(rules) = &mut self.batch {
            #[cfg(target_os = "macos")]
            init_firewall(rules, &self.ifname, default_policy)?;
            set_default_policy(rules, &self.ifname, default_policy.unwrap_or(Policy::Allow))?;
        } else {
            return Err(FirewallError::TransactionNotStarted);
        }
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
        debug!("Starting transaction");
        let rules = PfRules::default();
        self.batch = Some(rules);
        debug!("Started transaction");
        Ok(())
    }

    fn rollback(&mut self) {
        debug!("Rolling back transaction");
        self.batch = None;
        debug!("Rolled back transaction");
    }

    fn commit(&mut self) -> Result<(), FirewallError> {
        if let Some(changes) = self.batch.take() {
            debug!("Committing transaction");
            let mut transaction = Transaction::new();
            let anchor_change = AnchorChange::from(changes);
            eprintln!("Anchor change: {:?}", anchor_change);
            transaction.add_change(DEFGUARD_ANCHOR, anchor_change);
            transaction.commit()?;
            debug!("Committed transaction");
            Ok(())
        } else {
            return Err(FirewallError::TransactionNotStarted);
        }
    }
}

impl Protocol {
    pub const fn from_proto(
        proto: proto::enterprise::firewall::Protocol,
    ) -> Result<Self, FirewallError> {
        Ok(Self(proto as u8))
    }
}
