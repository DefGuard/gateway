use std::os::fd::AsRawFd;

use super::{
    calls::{pf_begin, pf_commit, pf_rollback, IocTrans, IocTransElement},
    rule::RuleSet,
    FirewallRule,
};
use crate::enterprise::firewall::{
    api::{FirewallApi, FirewallManagementApi},
    FirewallError, Policy,
};

impl FirewallManagementApi for FirewallApi {
    fn setup(
        &mut self,
        default_policy: Policy,
        _priority: Option<i32>,
    ) -> Result<(), FirewallError> {
        self.default_policy = default_policy;
        Ok(())
    }

    /// Clean up the firewall rules.
    fn cleanup(&mut self) -> Result<(), FirewallError> {
        Ok(())
    }

    /// Add firewall `rules`.
    fn add_rules(&mut self, rules: Vec<FirewallRule>) -> Result<(), FirewallError> {
        let anchor = &self.anchor();
        // Begin transaction.
        debug!("Begin pf transaction.");
        let mut elements = [IocTransElement::new(RuleSet::Filter, anchor)];
        let mut ioc_trans = IocTrans::new(elements.as_mut_slice());
        // This will create an anchor if it doesn't exist.
        unsafe {
            pf_begin(self.fd(), &mut ioc_trans)?;
        }

        let ticket = elements[0].ticket;
        let pool_ticket = self.get_pool_ticket(anchor)?;

        // Create first rule from the default policy.
        if let Err(err) = self.add_rule_policy(ticket, pool_ticket, anchor) {
            error!("Default policy rule can't be added.");
            debug!("Rollback pf transaction.");
            // Rule cannot be added, so rollback.
            unsafe {
                pf_rollback(self.fd(), &mut ioc_trans)?;
                return Err(FirewallError::TransactionFailed(err.to_string()));
            }
        }

        for mut rule in rules {
            if let Err(err) = self.add_rule(&mut rule, ticket, pool_ticket, anchor) {
                error!("Firewall rule {} can't be added.", &rule.id);
                debug!("Rollback pf transaction.");
                // Rule cannot be added, so rollback.
                unsafe {
                    pf_rollback(self.fd(), &mut ioc_trans)?;
                    return Err(FirewallError::TransactionFailed(err.to_string()));
                }
            }
        }

        // Commit transaction.
        debug!("Commit pf transaction.");
        unsafe {
            pf_commit(self.file.as_raw_fd(), &mut ioc_trans).unwrap();
        }

        Ok(())
    }

    /// Set default firewall policy.
    fn set_firewall_default_policy(&mut self, policy: Policy) -> Result<(), FirewallError> {
        self.default_policy = policy;
        Ok(())
    }

    /// Set masquerade status.
    fn set_masquerade_status(&mut self, _enabled: bool) -> Result<(), FirewallError> {
        Ok(())
    }

    /// Begin rule transaction.
    fn begin(&mut self) -> Result<(), FirewallError> {
        // TODO: remove this no-op.
        Ok(())
    }

    /// Commit rule transaction.
    fn commit(&mut self) -> Result<(), FirewallError> {
        // TODO: remove this no-op.
        Ok(())
    }

    /// Rollback rule transaction.
    fn rollback(&mut self) {
        // TODO: remove this no-op.
    }
}
