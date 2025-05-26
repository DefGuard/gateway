//! Interface to Packet Filter.
//!
//! Source code:
//!
//! Darwin:
//! - https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/pfvar.h
//!
//! FreeBSD:
//! - https://github.com/freebsd/freebsd-src/blob/main/sys/net/pfvar.h
//! - https://github.com/freebsd/freebsd-src/blob/main/sys/netpfil/pf/pf.h
//!
//! https://man.netbsd.org/pf.4
//! https://man.freebsd.org/cgi/man.cgi?pf
//! https://man.openbsd.org/pf.4

mod calls;
mod rule;
mod ticket;

use std::os::fd::{AsRawFd, RawFd};

use calls::pf_rollback;
use rule::PacketFilterRule;

use self::{
    calls::{pf_add_rule, pf_begin, pf_commit, Change, IocRule, IocTrans, IocTransElement, Rule},
    rule::RuleSet,
    ticket::get_pool_ticket,
};
use crate::enterprise::firewall::Port;

use super::{
    api::{FirewallApi, FirewallManagementApi},
    FirewallError, FirewallRule, Policy,
};

const ANCHOR_PREFIX: &str = "defguard/";

impl FirewallApi {
    /// Construct anchor name based on prefix and network interface name.
    fn anchor(&self) -> String {
        ANCHOR_PREFIX.to_owned() + &self.ifname
    }

    /// Return raw file descriptor to Packet Filter device.
    fn fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }

    fn add_rule_policy(
        &mut self,
        ticket: u32,
        pool_ticket: u32,
        anchor: &str,
    ) -> Result<(), FirewallError> {
        let rule = PacketFilterRule::for_policy(self.default_policy, &self.ifname);
        warn!("==> {rule}");
        let mut ioc = IocRule::with_rule(anchor, Rule::from_pf_rule(&rule));
        ioc.ticket = ticket;
        ioc.pool_ticket = pool_ticket;
        if let Err(err) = unsafe { pf_add_rule(self.fd(), &mut ioc) } {
            error!("Packet filter rule {rule} can't be added.");
            return Err(err.into());
        }

        Ok(())
    }

    /// Add a single firewall `rule`.
    fn add_rule(
        &mut self,
        rule: &mut FirewallRule,
        ticket: u32,
        pool_ticket: u32,
        anchor: &str,
    ) -> Result<(), FirewallError> {
        warn!("add_rule {rule:?}");
        let rules = PacketFilterRule::from_firewall_rule(&self.ifname, rule);

        for rule in rules {
            warn!("--> {rule}");
            let mut ioc = IocRule::with_rule(anchor, Rule::from_pf_rule(&rule));
            ioc.action = Change::None;
            ioc.ticket = ticket;
            ioc.pool_ticket = pool_ticket;
            if let Err(err) = unsafe { pf_add_rule(self.fd(), &mut ioc) } {
                error!("Packet filter rule {rule} can't be added.");
                return Err(err.into());
            }
        }

        Ok(())
    }
}

#[cfg(not(test))]
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
        let pool_ticket = get_pool_ticket(self.fd(), anchor)?;

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
    fn set_masquerade_status(&mut self, enabled: bool) -> Result<(), FirewallError> {
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
