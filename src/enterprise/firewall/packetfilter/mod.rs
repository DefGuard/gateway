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

use std::os::fd::{AsRawFd, RawFd};

use calls::{pf_begin_addrs, IocPoolAddr};
use rule::PacketFilterRule;

use self::calls::{pf_add_rule, Change, IocRule, Rule};
use super::{api::FirewallApi, FirewallError, FirewallRule};
use crate::enterprise::firewall::Port;

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

    fn get_pool_ticket(&self, anchor: &str) -> Result<u32, FirewallError> {
        let mut ioc = IocPoolAddr::new(anchor);

        unsafe {
            pf_begin_addrs(self.fd(), &raw mut ioc)?;
        }

        Ok(ioc.ticket)
    }

    fn add_rule_policy(
        &mut self,
        ticket: u32,
        pool_ticket: u32,
        anchor: &str,
    ) -> Result<(), FirewallError> {
        let rule = PacketFilterRule::for_policy(self.default_policy, &self.ifname);
        let mut ioc = IocRule::with_rule(anchor, Rule::from_pf_rule(&rule));
        ioc.ticket = ticket;
        ioc.pool_ticket = pool_ticket;
        if let Err(err) = unsafe { pf_add_rule(self.fd(), &raw mut ioc) } {
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
        debug!("add_rule {rule:?}");
        let rules = PacketFilterRule::from_firewall_rule(&self.ifname, rule);

        for rule in rules {
            let mut ioc = IocRule::with_rule(anchor, Rule::from_pf_rule(&rule));
            ioc.action = Change::None;
            ioc.ticket = ticket;
            ioc.pool_ticket = pool_ticket;
            if let Err(err) = unsafe { pf_add_rule(self.fd(), &raw mut ioc) } {
                error!("Packet filter rule {rule} can't be added.");
                return Err(err.into());
            }
        }

        Ok(())
    }
}

#[cfg(not(test))]
mod api;
