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
    calls::{
        pf_add_rule, pf_begin, pf_change_rule, pf_commit, Change, IocRule, IocTrans,
        IocTransElement, Rule,
    },
    rule::{Action, Direction, RuleSet},
    ticket::{get_pool_ticket, get_ticket},
};
use crate::enterprise::firewall::Port;

use super::{
    api::{FirewallApi, FirewallManagementApi},
    FirewallError, FirewallRule, Policy,
};

/*
impl PacketFilter {
    pub fn new() -> std::io::Result<Self> {
        let file = OpenOptions::new().read(true).write(true).open(DEV_PF)?;
        Ok(Self { file })
    }

    pub fn enable(&self) {
        unsafe {
            calls::pf_start(self.file.as_raw_fd()).unwrap();
        }
    }

    /// Return ticket for filter rules.
    pub fn begin(&self, anchor: &str) -> u32 {
        let element = IocTransElement::new(RuleSet::Filter, anchor);
        // let mut elements = vec![element];
        let mut elements = [element];
        let mut ioc_trans = IocTrans::new(elements.as_mut_slice());

        // This will create an anchor.
        unsafe {
            pf_begin(self.file.as_raw_fd(), &mut ioc_trans).unwrap();
        }

        elements[0].ticket
    }

    // TODO: expand
    pub fn add_rule(&self, src: IpNetwork, src_port: Port, anchor: &str) {
        // let ticket = self.begin(anchor);

        let element = IocTransElement::new(RuleSet::Filter, anchor);
        // let mut elements = vec![element];
        let mut elements = [element];
        let mut ioc_trans = IocTrans::new(elements.as_mut_slice());

        // This will create an anchor.
        unsafe {
            pf_begin(self.file.as_raw_fd(), &mut ioc_trans).unwrap();
        }

        let ticket = elements[0].ticket;

        // ---
        let pool_ticket = get_pool_ticket(self.file.as_raw_fd(), anchor);

        let mut rule = Rule::new(src, src_port);
        // rule.action = Change::AddTail; FreeBSD/OpenBSD only?
        rule.direction = Direction::In;

        // eprintln!("Src {:?}", rule.src);
        // eprintln!("Dst {:?}", rule.dst);
        eprintln!("{:?}", rule);

        let mut ioc = IocRule::with_rule(anchor, rule);
        ioc.action = Change::None;
        ioc.ticket = ticket;
        ioc.pool_ticket = pool_ticket;

        // pf_add_rule returns EBUSY on macOS.
        unsafe {
            pf_add_rule(self.file.as_raw_fd(), &mut ioc).unwrap();
            pf_commit(self.file.as_raw_fd(), &mut ioc_trans).unwrap();
        }
    }

    // TODO: expand
    pub fn append_rule(&self, src: IpNetwork, src_port: Port, anchor: &str) {
        // OpenBSD has no pool tickets
        // #[cfg(any(target_os = "macos", target_os = "freebsd"))]
        let pool_ticket = get_pool_ticket(self.file.as_raw_fd(), anchor);
        let ticket = get_ticket(self.file.as_raw_fd(), anchor, Action::Pass);

        eprintln!("Ticket {ticket}, pool ticket {pool_ticket}");

        let mut rule = Rule::new(src, src_port);
        // rule.action = Change::AddTail; FreeBSD/OpenBSD only?
        rule.direction = Direction::In;

        let mut ioc = IocRule::with_rule(anchor, rule);
        ioc.action = Change::AddHead;
        ioc.ticket = ticket;
        ioc.pool_ticket = pool_ticket;

        // pf_add_rule returns EBUSY on macOS.
        unsafe {
            // pf_add_rule(self.file.as_raw_fd(), &mut ioc).unwrap();
            pf_change_rule(self.file.as_raw_fd(), &mut ioc).unwrap();
        }
    }

    // Add anchor with a given `name`.
    // FIXME: This method only works on macOS.
    // pub fn add_anchor(&self, name: &str) {
    //     // #[cfg(target_os = "macos")]
    //     // {
    //     //     pfioc_rule.rule.action = kind.into();
    //     // }
    //     // #[cfg(any(target_os = "freebsd", target_os = "openbsd"))]
    //     // {
    //     //     pfioc_rule.rule.action = PF_CHANGE_REMOVE as u8;
    //     // }

    //     // FIXME: empty
    //     let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
    //     let mut rule = Rule::new(src);

    //     #[cfg(any(target_os = "freebsd", target_os = "netbsd", target_os = "openbsd"))]
    //     {
    //         rule.action = Action::NoNat; // = Change::Remove
    //     }

    //     let mut ioc = IocRule {
    //         action: Change::None,
    //         ticket: 0,
    //         pool_ticket: 0,
    //         nr: 0,
    //         anchor: [0; 1024],
    //         anchor_call: [0; 1024],
    //         rule,
    //     };
    //     name.bytes()
    //         .take(1023)
    //         .enumerate()
    //         .for_each(|(i, b)| ioc.anchor_call[i] = b);

    //     // unsafe { pf_insert_rule(self.file.as_raw_fd(), &mut ioc).unwrap() };
    //     unsafe { pf_change_rule(self.file.as_raw_fd(), &mut ioc).unwrap() };
    // }
}
*/

const ANCHOR_PREFIX: &str = "defguard";

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
        let rules = PacketFilterRule::from_firewall_rule(rule);

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
