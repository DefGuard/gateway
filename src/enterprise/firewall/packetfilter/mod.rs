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
#[cfg(any(target_os = "freebsd", target_os = "macos"))]
mod monitor;
mod rule;

use std::os::fd::{AsRawFd, RawFd};

use defguard_wireguard_rs::bsd::c_int_to_error;
use libc::ioctl;

#[cfg(any(target_os = "freebsd", target_os = "macos"))]
pub use self::monitor::ConnectionMonitor;
use self::{
    calls::{DIOCADDRULE, DIOCBEGINADDRS, IocPoolAddr, IocRule, Rule},
    rule::PacketFilterRule,
};
use super::{FirewallError, FirewallRule, Policy, api::FirewallApi};
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

        let result = unsafe { ioctl(self.fd(), DIOCBEGINADDRS, &raw mut ioc) };
        c_int_to_error(result)?;

        Ok(ioc.ticket)
    }

    /// Add `rule` to `anchor`.
    fn add_rule(
        &self,
        rule: &PacketFilterRule,
        ticket: u32,
        pool_ticket: u32,
        anchor: &str,
    ) -> Result<(), FirewallError> {
        debug!("Adding Packet Filter rule {rule}");
        let mut ioc = IocRule::with_rule(anchor, Rule::from_pf_rule(rule));
        ioc.ticket = ticket;
        ioc.pool_ticket = pool_ticket;
        let result = unsafe { ioctl(self.fd(), DIOCADDRULE, &raw mut ioc) };
        if let Err(err) = c_int_to_error(result) {
            error!("Packet filter rule {rule} can't be added.");
            return Err(err.into());
        }

        Ok(())
    }
}

/// Rules in the Defguard anchor, in order, with the Defguard rule ID each one comes from.
/// Also used by the connection monitor to map logged rule numbers to Defguard rules.
/// Rules log to pflog unit `log`, if set.
fn anchor_rules(
    ifname: &str,
    default_policy: Policy,
    rules: &[FirewallRule],
    log: Option<u8>,
) -> Vec<(PacketFilterRule, Option<i64>)> {
    let mut anchor_rules = vec![
        (
            PacketFilterRule::for_policy(default_policy, ifname, log),
            None,
        ),
        (PacketFilterRule::for_inbound(ifname, log), None),
    ];
    for rule in rules {
        anchor_rules.extend(
            PacketFilterRule::from_firewall_rule(ifname, rule, log)
                .into_iter()
                .map(|pf_rule| (pf_rule, Some(rule.id))),
        );
    }
    anchor_rules
}

mod api;
