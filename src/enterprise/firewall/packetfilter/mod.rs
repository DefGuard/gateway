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

const ANCHOR_PREFIX: &str = "defguard.";

impl FirewallApi {
    fn anchor(&self) -> String {
        ANCHOR_PREFIX.to_owned() + &self.ifname
    }

    fn fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }

    /// Add fireall `rules`.
    fn add_rule(
        &mut self,
        rule: FirewallRule,
        ticket: u32,
        pool_ticket: u32,
        anchor: &str,
    ) -> Result<(), FirewallError> {
        warn!("add_rule {rule:?}");
        let rules = PacketFilterRule::from_firewall_rule(&self.ifname, rule);
        warn!("--> rules {rules:?}");

        for rule in rules {
            let mut ioc = IocRule::with_rule(anchor, Rule::from_pf_rule(&rule));
            ioc.action = Change::None;
            ioc.ticket = ticket;
            ioc.pool_ticket = pool_ticket;
            unsafe {
                pf_add_rule(self.fd(), &mut ioc)?;
            }
        }

        Ok(())
    }
}

#[cfg(not(test))]
impl FirewallManagementApi for FirewallApi {
    fn setup(
        &mut self,
        _default_policy: Policy,
        _priority: Option<i32>,
    ) -> Result<(), FirewallError> {
        Ok(())
    }

    /// Clean up the firewall rules.
    fn cleanup(&mut self) -> Result<(), FirewallError> {
        Ok(())
    }

    /// Add fireall `rules`.
    fn add_rules(&mut self, rules: Vec<FirewallRule>) -> Result<(), FirewallError> {
        let anchor = &self.anchor();
        // Begin transaction.
        let element = IocTransElement::new(RuleSet::Filter, anchor);
        let mut elements = [element];
        let mut ioc_trans = IocTrans::new(elements.as_mut_slice());
        // This will create an anchor if it doesn't exist.
        unsafe {
            pf_begin(self.fd(), &mut ioc_trans)?;
        }

        let ticket = elements[0].ticket;
        let pool_ticket = get_pool_ticket(self.fd(), anchor);

        for rule in rules {
            if let Err(err) = self.add_rule(rule, ticket, pool_ticket, anchor) {
                unsafe {
                    pf_rollback(self.fd(), &mut ioc_trans)?;
                    return Err(FirewallError::TransactionFailed(err.to_string()));
                }
            }
        }

        unsafe {
            pf_commit(self.file.as_raw_fd(), &mut ioc_trans).unwrap();
        }

        Ok(())
    }

    /// Set default firewall policy.
    fn set_firewall_default_policy(&mut self, policy: Policy) -> Result<(), FirewallError> {
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
