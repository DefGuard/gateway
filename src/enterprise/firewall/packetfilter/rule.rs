use ipnetwork::IpNetwork;
use libc::{AF_INET, AF_INET6, AF_UNSPEC};

use super::{FirewallRule, Port};
use crate::enterprise::firewall::{Policy, Protocol};

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

/// TODO: convert to `const`
#[repr(u8)]
pub enum LogFlags {
    /// PF_LOG = 0x01
    Log = 1,
    /// PF_LOG_ALL = 0x02
    All = 2,
    /// PF_LOG_SOCKET_LOOKUP = 0x04,
    SocketLookup = 4,
    /// PF_LOG_FORCE = 0x08
    #[cfg(target_os = "freebsd")]
    Force = 8,
    /// PF_LOG_MATCHES = 0x10
    #[cfg(target_os = "freebsd")]
    Matches = 16,
}

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
    /// See `TcpFlags`.
    pub(crate) tcp_flags: u8,
    pub(crate) label: Option<String>,
}

impl PacketFilterRule {
    /// Determine address family based on `from` field.
    pub(crate) fn address_family(&self) -> AddressFamily {
        match self.from {
            None => AddressFamily::Unspec,
            Some(IpNetwork::V4(_)) => AddressFamily::Inet,
            Some(IpNetwork::V6(_)) => AddressFamily::Inet6,
        }
    }

    pub(crate) fn from_firewall_rule(fr: FirewallRule) -> Vec<Self> {
        let mut rules = Vec::new();
        let action = match fr.verdict {
            Policy::Allow => Action::Pass,
            Policy::Deny => Action::Drop,
        };

        // TODO: use Any source address
        for dest in &fr.destination_addrs {
            if fr.destination_ports.is_empty() {
                // use Port::Any
                let rule = Self {
                    from: None,
                    from_port: Port::Any,
                    to: None,
                    to_port: Port::Any,
                    action,
                    direction: Direction::InOut,
                    quick: false,
                    log: 0,
                    keep_state: State::None,
                    interface: None,
                    proto: Protocol::Any, // TODO: iterate
                    tcp_flags: 0,
                    label: fr.comment.clone(),
                };
                rules.push(rule);
            } else {
                for port in &fr.destination_ports {
                    //
                }
            }
        }

        rules
    }
}

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

/// As defined in `netinet/tcp.h`.
#[repr(u8)]
pub enum TcpFlags {
    Any,
    // TH_FIN = 0x01; Final: Set on the last segment.
    Fin = 1,
    // TH_SYN = 0x02; Synchronization: New conn with dst port.
    Syn = 2,
    // TH_RST = 0x04; Reset: Announce to peer conn terminated.
    Rst = 4,
    // TH_PUSH = 0x08; Push: Immediately send, don't buffer seg.
    Push = 8,
    // TH_ACK = 0x10; Acknowledge: Part of connection establish.
    Ack = 16,
    // TH_URG = 0x20; Urgent: send special marked segment now.
    Urg = 32,
    // TH_ECE = 0x40; ECN Echo.
    Ece = 64,
    // TH_CWR = 0x80; Congestion Window Reduced.
    Cwr = 128,
}
