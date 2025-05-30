use std::fmt;

use ipnetwork::IpNetwork;
use libc::{AF_INET, AF_INET6, AF_UNSPEC};

use super::{FirewallRule, Port};
use crate::enterprise::firewall::{Address, Policy, Protocol};

/// Packet filter rule action.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum Action {
    /// PF_PASS = 0,
    Pass,
    // PF_DROP = 1,
    Drop,
    // PF_SCRUB = 2,
    Scrub,
    // PF_NOSCRUB = 3,
    NoScrub,
    // PF_NAT = 4,
    Nat,
    // PF_NONAT = 5,
    NoNat,
    // PF_BINAT = 6,
    BiNat,
    // PF_NOBINAT = 7,
    NoBiNat,
    // PF_RDR = 8,
    Redirect,
    // PF_NORDR = 9,
    NoRedirect,
    // PF_SYNPROXY_DROP = 10,
    // PF_DUMMYNET = 11,
    // PF_NODUMMYNET = 12,
    // PF_NAT64 = 13,
    // PF_NONAT64 = 14,
}

impl fmt::Display for Action {
    /// Display `Action` as pf.conf keyword.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let action = match self {
            Self::Pass => "pass",
            Self::Drop => "block drop",
            Self::Scrub => "scrub",
            Self::NoScrub => "block scrub",
            Self::Nat => "nat",
            Self::NoNat => "block nat",
            Self::BiNat => "binat",
            Self::NoBiNat => "block binat",
            Self::Redirect => "rdr",
            Self::NoRedirect => "block rdr",
        };
        write!(f, "{action}")
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub(super) enum AddressFamily {
    Unspec = AF_UNSPEC as u8,
    Inet = AF_INET as u8,
    Inet6 = AF_INET6 as u8,
}

/// Packet filter rule direction.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum Direction {
    /// PF_INOUT = 0
    InOut,
    /// PF_IN = 1
    In,
    /// PF_OUT = 2
    Out,
}

impl fmt::Display for Direction {
    /// Display `Direction` as pf.conf keyword.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let direction = match self {
            Self::InOut => "",
            Self::In => "in",
            Self::Out => "out",
        };
        write!(f, "{direction}")
    }
}

const PF_LOG: u8 = 0x01;
// const PF_LOG_ALL: u8 = 0x02;
// const PF_LOG_SOCKET_LOOKUP: u8 = 0x04;
// #[cfg(target_os = "freebsd")]
// const PF_LOG_FORCE: u8 = 0x08;
// #[cfg(target_os = "freebsd")]
// const PF_LOG_MATCHES: u8 = 0x10;

/// Equivalent to `PF_RULESET_...`.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
#[repr(i32)]
pub enum RuleSet {
    /// PF_RULESET_SCRUB = 0
    Scrub,
    /// PF_RULESET_FILTER = 1
    Filter,
    /// PF_RULESET_NAT = 2
    Nat,
    /// PF_RULESET_BINAT = 3
    BiNat,
    /// PF_RULESET_RDR = 4
    Redirect,
    /// PF_RULESET_ALTQ = 5
    Altq,
    /// PF_RULESET_TABLE = 6
    Table,
    /// PF_RULESET_ETH = 7
    Eth,
}

// Equivalent to `PF_STATE_...`.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum State {
    // Don't keep state.
    None = 0,
    // PF_STATE_NORMAL = 1
    Normal = 1,
    // PF_STATE_MODULATE = 2
    Modulate = 2,
    // PF_STATE_SYNPROXY = 3
    SynProxy = 3,
}

impl fmt::Display for State {
    /// Display `State` as in pf.conf.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = match self {
            Self::None => "no state",
            Self::Normal => "keep state",
            Self::Modulate => "modulate state",
            Self::SynProxy => "synproxy state",
        };
        write!(f, "{state}")
    }
}

/// TCP flags as defined in `netinet/tcp.h`.
/// Final: Set on the last segment.
#[allow(dead_code)]
const TH_FIN: u8 = 0x01;
/// Synchronization: New conn with dst port.
const TH_SYN: u8 = 0x02;
/// Reset: Announce to peer conn terminated.
#[allow(dead_code)]
const TH_RST: u8 = 0x04;
/// Push: Immediately send, don't buffer seg.
#[allow(dead_code)]
const TH_PUSH: u8 = 0x08;
/// Acknowledge: Part of connection establish.
const TH_ACK: u8 = 0x10;
/// Urgent: send special marked segment now.
#[allow(dead_code)]
const TH_URG: u8 = 0x20;
/// ECN Echo.
#[allow(dead_code)]
const TH_ECE: u8 = 0x40;
/// Congestion Window Reduced.
#[allow(dead_code)]
const TH_CWR: u8 = 0x80;

#[derive(Debug)]
pub(super) struct PacketFilterRule {
    /// Source address; `Option::None` means "any".
    pub(super) from: Option<IpNetwork>,
    /// Source port; 0 means "any".
    pub(super) from_port: Port,
    /// Destination address; `Option::None` means "any".
    pub(super) to: Option<IpNetwork>,
    /// Destination port; 0 means "any".
    pub(super) to_port: Port,
    pub(super) action: Action,
    pub(super) direction: Direction,
    pub(super) quick: bool,
    /// See `PF_LOG`.
    pub(super) log: u8,
    pub(super) state: State,
    pub(super) interface: Option<String>,
    pub(super) proto: Protocol,
    pub(super) tcp_flags: u8,
    pub(super) tcp_flags_set: u8,
    pub(super) label: Option<String>,
}

impl PacketFilterRule {
    /// Default rule for policy.
    #[must_use]
    pub(super) fn for_policy(policy: Policy, ifname: &str) -> Self {
        let (action, state) = match policy {
            Policy::Allow => (Action::Pass, State::Normal),
            Policy::Deny => (Action::Drop, State::None),
        };
        Self {
            from: None,
            from_port: Port::Any,
            to: None,
            to_port: Port::Any,
            action,
            direction: Direction::In,
            quick: false,
            log: PF_LOG,
            state,
            interface: Some(ifname.to_owned()),
            proto: Protocol::Any,
            tcp_flags: TH_SYN,
            tcp_flags_set: TH_SYN | TH_ACK,
            label: None,
        }
    }

    /// Determine address family.
    pub(super) fn address_family(&self) -> AddressFamily {
        match self.to {
            None => match self.from {
                None => AddressFamily::Unspec,
                Some(IpNetwork::V4(_)) => AddressFamily::Inet,
                Some(IpNetwork::V6(_)) => AddressFamily::Inet6,
            },
            Some(IpNetwork::V4(_)) => AddressFamily::Inet,
            Some(IpNetwork::V6(_)) => AddressFamily::Inet6,
        }
    }

    /// Expand `FirewallRule` into a set of `PacketFilterRule`s.
    pub(super) fn from_firewall_rule(ifname: &str, fr: &mut FirewallRule) -> Vec<Self> {
        let mut rules = Vec::new();
        let (action, state) = match fr.verdict {
            Policy::Allow => (Action::Pass, State::Normal),
            Policy::Deny => (Action::Drop, State::None),
        };

        let mut from_addrs = Vec::new();
        if fr.source_addrs.is_empty() {
            from_addrs.push(None);
        } else {
            for src in &fr.source_addrs {
                match src {
                    Address::Network(net) => from_addrs.push(Some(*net)),
                    Address::Range(range) => {
                        for addr in range.clone() {
                            from_addrs.push(Some(IpNetwork::from(addr)));
                        }
                    }
                }
            }
        }

        let mut to_addrs = Vec::new();
        if fr.destination_addrs.is_empty() {
            to_addrs.push(None);
        } else {
            for src in &fr.destination_addrs {
                match src {
                    Address::Network(net) => to_addrs.push(Some(*net)),
                    Address::Range(range) => {
                        for addr in range.clone() {
                            to_addrs.push(Some(IpNetwork::from(addr)));
                        }
                    }
                }
            }
        }

        if fr.destination_ports.is_empty() {
            fr.destination_ports.push(Port::Any);
        }

        if fr.protocols.is_empty() {
            fr.protocols.push(Protocol::Any);
        }

        for from in &from_addrs {
            for to in &to_addrs {
                for to_port in &fr.destination_ports {
                    for proto in &fr.protocols {
                        let rule = Self {
                            from: *from,
                            from_port: Port::Any,
                            to: *to,
                            to_port: *to_port,
                            action,
                            direction: Direction::In,
                            // Enable quick to match NFTables behaviour.
                            quick: true,
                            log: PF_LOG,
                            state,
                            interface: Some(ifname.to_owned()),
                            proto: *proto,
                            // For stateful connections, the default is flags S/SA.
                            tcp_flags: TH_SYN,
                            tcp_flags_set: TH_SYN | TH_ACK,
                            label: fr.comment.clone(),
                        };
                        rules.push(rule);
                    }
                }
            }
        }

        rules
    }
}

impl fmt::Display for PacketFilterRule {
    // Display `PacketFilterRule` in similar format to rules in pf.conf.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.action, self.direction)?;
        // TODO: log
        if self.quick {
            write!(f, " quick")?;
        }
        if let Some(interface) = &self.interface {
            write!(f, " on {interface}")?;
        }
        write!(f, " from")?;
        if let Some(from) = self.from {
            write!(f, " {from}")?;
        } else {
            write!(f, " any")?;
        }
        write!(f, " {} to", self.from_port)?;
        if let Some(to) = self.to {
            write!(f, " {to}")?;
        } else {
            write!(f, " any")?;
        }
        // TODO: tcp_flags/tcp_flags_set
        write!(f, " {} {}", self.to_port, self.state)?;
        if let Some(label) = &self.label {
            write!(f, " label \"{label}\"")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    #[test]
    fn unroll_firewall_rule() {
        // Empty rule
        let mut fr = FirewallRule {
            comment: None,
            destination_addrs: Vec::new(),
            destination_ports: Vec::new(),
            id: 0,
            verdict: Policy::Allow,
            protocols: Vec::new(),
            source_addrs: Vec::new(),
            ipv4: true,
        };

        let rules = PacketFilterRule::from_firewall_rule("lo0", &mut fr);
        assert_eq!(1, rules.len());
        assert_eq!(
            rules[0].to_string(),
            "pass out quick on lo0 from any  to any  keep state"
        );

        // One address, one port.
        let addr1 = Address::Network(
            IpNetwork::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 24).unwrap(),
        );
        let mut fr = FirewallRule {
            comment: None,
            destination_addrs: vec![addr1],
            destination_ports: vec![Port::Single(1138)],
            id: 0,
            verdict: Policy::Allow,
            protocols: Vec::new(),
            source_addrs: Vec::new(),
            ipv4: true,
        };

        let rules = PacketFilterRule::from_firewall_rule("lo0", &mut fr);
        assert_eq!(1, rules.len());
        assert_eq!(
            rules[0].to_string(),
            "pass out quick on lo0 from any  to 192.168.1.10/24 port = 1138 keep state"
        );

        // Two addresses, two ports.
        let addr1 = Address::Network(
            IpNetwork::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 24).unwrap(),
        );
        let addr2 = Address::Network(
            IpNetwork::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)), 24).unwrap(),
        );
        let mut fr = FirewallRule {
            comment: None,
            destination_addrs: vec![addr1, addr2],
            destination_ports: vec![Port::Single(1138), Port::Single(42)],
            id: 0,
            verdict: Policy::Allow,
            protocols: Vec::new(),
            source_addrs: Vec::new(),
            ipv4: true,
        };

        let rules = PacketFilterRule::from_firewall_rule("lo0", &mut fr);
        assert_eq!(4, rules.len());
        assert_eq!(
            rules[0].to_string(),
            "pass out quick on lo0 from any  to 192.168.1.10/24 port = 1138 keep state"
        );
        assert_eq!(
            rules[1].to_string(),
            "pass out quick on lo0 from any  to 192.168.1.10/24 port = 42 keep state"
        );
        assert_eq!(
            rules[2].to_string(),
            "pass out quick on lo0 from any  to 192.168.1.20/24 port = 1138 keep state"
        );
        assert_eq!(
            rules[3].to_string(),
            "pass out quick on lo0 from any  to 192.168.1.20/24 port = 42 keep state"
        );
    }
}
