use std::os::fd::AsRawFd;

use defguard_wireguard_rs::bsd::c_int_to_error;
use libc::ioctl;

use super::{
    FirewallRule, anchor_rules,
    calls::{DIOCXBEGIN, DIOCXCOMMIT, DIOCXROLLBACK, IocTrans, IocTransElement},
    rule::RuleSet,
};
use crate::enterprise::firewall::{
    FirewallError, Policy, SnatBinding,
    api::{FirewallApi, FirewallManagementApi},
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
    fn add_rules(&mut self, rules: &[FirewallRule]) -> Result<(), FirewallError> {
        let anchor = &self.anchor();
        // Begin transaction.
        debug!("Begin pf transaction");
        let mut elements = [IocTransElement::new(RuleSet::Filter, anchor)];
        let mut ioc_trans = IocTrans::new(elements.as_mut_slice());
        // This will create an anchor if it doesn't exist.
        let result = unsafe { ioctl(self.fd(), DIOCXBEGIN, &raw mut ioc_trans) };
        c_int_to_error(result)?;

        let ticket = elements[0].ticket;
        let pool_ticket = self.get_pool_ticket(anchor)?;

        for (rule, _) in anchor_rules(&self.ifname, self.default_policy, rules) {
            if let Err(err) = self.add_rule(&rule, ticket, pool_ticket, anchor) {
                debug!("Rollback pf transaction");
                // Rule cannot be added, so rollback.
                let result = unsafe { ioctl(self.fd(), DIOCXROLLBACK, &raw mut ioc_trans) };
                c_int_to_error(result)?;

                return Err(FirewallError::TransactionFailed(err.to_string()));
            }
        }

        // Commit transaction.
        debug!("Commit pf transaction");
        let result = unsafe { ioctl(self.file.as_raw_fd(), DIOCXCOMMIT, &raw mut ioc_trans) };
        c_int_to_error(result)?;

        Ok(())
    }

    /// Setup Network Address Translation using POSTROUTING chain rules
    fn setup_nat(
        &mut self,
        _masquerade_enabled: bool,
        _snat_bindings: &[SnatBinding],
    ) -> Result<(), FirewallError> {
        Ok(())
    }
}
