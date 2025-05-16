use ipnetwork::IpNetwork;
use libc::{AF_INET, AF_INET6, AF_UNSPEC};

use super::{FirewallRule, Port};
use crate::enterprise::firewall::{Address, Policy, Protocol};

/// Packet filter rule action.
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

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub(crate) enum AddressFamily {
    Unspec = AF_UNSPEC as u8,
    Inet = AF_INET as u8,
    Inet6 = AF_INET6 as u8,
}

/// Packet filter rule direction.
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

const PF_LOG: u8 = 0x01;
const PF_LOG_ALL: u8 = 0x02;
const PF_LOG_SOCKET_LOOKUP: u8 = 0x04;
#[cfg(target_os = "freebsd")]
const PF_LOG_FORCE: u8 = 0x08;
#[cfg(target_os = "freebsd")]
const PF_LOG_MATCHES: u8 = 0x10;

/// Equivalent to `PF_RULESET_...`.
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

/// TCP flags as defined in `netinet/tcp.h`.
/// Final: Set on the last segment.
const TH_FIN: u8 = 0x01;
/// Synchronization: New conn with dst port.
const TH_SYN: u8 = 0x02;
/// Reset: Announce to peer conn terminated.
const TH_RST: u8 = 0x04;
/// Push: Immediately send, don't buffer seg.
const TH_PUSH: u8 = 0x08;
/// Acknowledge: Part of connection establish.
const TH_ACK: u8 = 0x10;
/// Urgent: send special marked segment now.
const TH_URG: u8 = 0x20;
/// ECN Echo.
const TH_ECE: u8 = 0x40;
/// Congestion Window Reduced.
const TH_CWR: u8 = 0x80;

#[derive(Debug)]
pub struct PacketFilterRule {
    /// Source address; `Option::None` means "any".
    pub(crate) from: Option<IpNetwork>,
    /// Source port; 0 means "any".
    pub(crate) from_port: Port,
    /// Destination address; `Option::None` means "any".
    pub(crate) to: Option<IpNetwork>,
    /// Destination port; 0 means "any".
    pub(crate) to_port: Port,
    pub(crate) action: Action,
    pub(crate) direction: Direction,
    pub(crate) quick: bool,
    /// See `LogFlags`.
    pub(crate) log: u8,
    pub(crate) keep_state: State,
    pub(crate) interface: Option<String>,
    pub(crate) proto: Protocol,
    pub(crate) tcp_flags: u8,
    pub(crate) tcp_flags_set: u8,
    pub(crate) label: Option<String>,
}

impl PacketFilterRule {
    /// Determine address family based on `to` field.
    pub(crate) fn address_family(&self) -> AddressFamily {
        match self.to {
            None => AddressFamily::Unspec,
            Some(IpNetwork::V4(_)) => AddressFamily::Inet,
            Some(IpNetwork::V6(_)) => AddressFamily::Inet6,
        }
    }

    /// Expand `FirewallRule` into a set of `PacketFilterRule`s.
    pub(crate) fn from_firewall_rule(ifname: &str, mut fr: FirewallRule) -> Vec<Self> {
        let mut rules = Vec::new();
        let action = match fr.verdict {
            Policy::Allow => Action::Pass,
            Policy::Deny => Action::Drop,
        };

        let mut from_addrs = Vec::new();
        if fr.source_addrs.is_empty() {
            from_addrs.push(None);
        } else {
            for src in fr.source_addrs {
                match src {
                    Address::Network(net) => from_addrs.push(Some(net)),
                    Address::Range(range) => {
                        for addr in range {
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
            for src in fr.destination_addrs {
                match src {
                    Address::Network(net) => to_addrs.push(Some(net)),
                    Address::Range(range) => {
                        for addr in range {
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
                            direction: Direction::InOut,
                            quick: false,
                            // Disable logging.
                            log: 0,
                            keep_state: State::Normal,
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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    #[test]
    fn unroll_firewall_rule() {
        // Empty rule
        let fr = FirewallRule {
            comment: None,
            destination_addrs: Vec::new(),
            destination_ports: Vec::new(),
            id: 0,
            verdict: Policy::Allow,
            protocols: Vec::new(),
            source_addrs: Vec::new(),
            ipv4: true,
        };

        let rules = PacketFilterRule::from_firewall_rule("lo0", fr);
        assert_eq!(1, rules.len());

        // One address, one port.
        let addr1 = Address::Network(
            IpNetwork::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 24).unwrap(),
        );
        let fr = FirewallRule {
            comment: None,
            destination_addrs: vec![addr1],
            destination_ports: vec![Port::Single(1138)],
            id: 0,
            verdict: Policy::Allow,
            protocols: Vec::new(),
            source_addrs: Vec::new(),
            ipv4: true,
        };

        let rules = PacketFilterRule::from_firewall_rule("lo0", fr);
        assert_eq!(1, rules.len());

        // Two addresses, two ports.
        let addr1 = Address::Network(
            IpNetwork::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 24).unwrap(),
        );
        let addr2 = Address::Network(
            IpNetwork::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)), 24).unwrap(),
        );
        let fr = FirewallRule {
            comment: None,
            destination_addrs: vec![addr1, addr2],
            destination_ports: vec![Port::Single(1138), Port::Single(42)],
            id: 0,
            verdict: Policy::Allow,
            protocols: Vec::new(),
            source_addrs: Vec::new(),
            ipv4: true,
        };

        let rules = PacketFilterRule::from_firewall_rule("lo0", fr);
        assert_eq!(4, rules.len());
    }
}
