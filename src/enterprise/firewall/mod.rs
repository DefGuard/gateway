pub mod api;
#[cfg(test)]
mod dummy;
mod iprange;
#[cfg(all(not(test), target_os = "linux"))]
mod nftables;
#[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "netbsd"))]
mod packetfilter;

use std::{fmt, net::IpAddr, str::FromStr};

use ipnetwork::IpNetwork;
use iprange::{IpAddrRange, IpAddrRangeError};
use thiserror::Error;

use crate::proto;

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Address {
    Network(IpNetwork),
    Range(IpAddrRange),
}

impl Address {
    pub fn from_proto(ip: &proto::enterprise::firewall::IpAddress) -> Result<Self, FirewallError> {
        match &ip.address {
            Some(proto::enterprise::firewall::ip_address::Address::Ip(ip)) => {
                Ok(Self::Network(IpNetwork::from_str(ip).map_err(|err| {
                    FirewallError::TypeConversionError(format!("Invalid IP format: {err}"))
                })?))
            }
            Some(proto::enterprise::firewall::ip_address::Address::IpSubnet(network)) => Ok(
                Self::Network(IpNetwork::from_str(network).map_err(|err| {
                    FirewallError::TypeConversionError(format!("Invalid subnet format: {err}"))
                })?),
            ),
            Some(proto::enterprise::firewall::ip_address::Address::IpRange(range)) => {
                let start = IpAddr::from_str(&range.start).map_err(|err| {
                    FirewallError::TypeConversionError(format!("Invalid IP format: {err}"))
                })?;
                let end = IpAddr::from_str(&range.end).map_err(|err| {
                    FirewallError::TypeConversionError(format!("Invalid IP format: {err}"))
                })?;
                if start > end {
                    return Err(FirewallError::TypeConversionError(format!(
                        "Invalid IP range: start IP ({start}) is greater than end IP ({end})",
                    )));
                }
                Ok(Self::Range(IpAddrRange::new(start, end)?))
            }
            None => Err(FirewallError::TypeConversionError(format!(
                "Invalid IP address type. Must be one of Ip, IpSubnet, IpRange. Instead got {:?}",
                ip.address
            ))),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub(crate) enum Port {
    Any, // currently it is handled with empty Vec<Port>
    Single(u16),
    Range(u16, u16),
}

impl Port {
    pub fn from_proto(port: &proto::enterprise::firewall::Port) -> Result<Self, FirewallError> {
        match &port.port {
            Some(proto::enterprise::firewall::port::Port::SinglePort(port)) => {
                let port_u16 = u16::try_from(*port).map_err(|err| {
                    FirewallError::TypeConversionError(format!(
                        "Invalid port number ({port}): {err}"
                    ))
                })?;
                Ok(Self::Single(port_u16))
            }
            Some(proto::enterprise::firewall::port::Port::PortRange(range)) => {
                let start_u16 = u16::try_from(range.start).map_err(|err| {
                    FirewallError::TypeConversionError(format!(
                        "Invalid range start port number ({}): {err}",
                        range.start
                    ))
                })?;
                let end_u16 = u16::try_from(range.end).map_err(|err| {
                    FirewallError::TypeConversionError(format!(
                        "Invalid range end port number ({}): {err}",
                        range.end
                    ))
                })?;
                if start_u16 > end_u16 {
                    return Err(FirewallError::TypeConversionError(format!(
                        "Invalid port range: start port ({start_u16}) is greater than end port ({end_u16})"
                    )));
                }
                Ok(Self::Range(start_u16, end_u16))
            }
            _ => Err(FirewallError::TypeConversionError(format!(
                "Invalid port type. Must be one of SinglePort, PortRange. Instead got: {:?}",
                port.port
            ))),
        }
    }
}

impl fmt::Display for Port {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Port::Any => Ok(()), // nothing here
            Port::Single(port) => write!(f, "port = {port}"),
            Port::Range(from, to) => write!(f, "port = {{{from}..{to}}}"),
        }
    }
}

/// As defined in `netinet/in.h`.
#[derive(Debug, Copy, Clone, PartialEq)]
#[repr(u8)]
pub(crate) enum Protocol {
    Any = libc::IPPROTO_IP as u8,
    Icmp = libc::IPPROTO_ICMP as u8,
    Tcp = libc::IPPROTO_TCP as u8,
    Udp = libc::IPPROTO_UDP as u8,
    IcmpV6 = libc::IPPROTO_ICMPV6 as u8,
}

impl Protocol {
    #[must_use]
    pub(crate) fn supports_ports(self) -> bool {
        matches!(self, Protocol::Tcp | Protocol::Udp)
    }

    pub(crate) const fn from_proto(
        proto: proto::enterprise::firewall::Protocol,
    ) -> Result<Self, FirewallError> {
        match proto {
            proto::enterprise::firewall::Protocol::Tcp => Ok(Self::Tcp),
            proto::enterprise::firewall::Protocol::Udp => Ok(Self::Udp),
            proto::enterprise::firewall::Protocol::Icmp => Ok(Self::Icmp),
            // TODO: IcmpV6
            proto::enterprise::firewall::Protocol::Invalid => {
                Err(FirewallError::UnsupportedProtocol(proto as u8))
            }
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let protocol = match self {
            Self::Any => "any",
            Self::Icmp => "icmp",
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::IcmpV6 => "icmp6",
        };
        write!(f, "{protocol}")
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub(crate) enum Policy {
    #[default]
    Allow,
    Deny,
}

impl From<bool> for Policy {
    fn from(allow: bool) -> Self {
        if allow {
            Self::Allow
        } else {
            Self::Deny
        }
    }
}

impl Policy {
    #[must_use]
    pub const fn from_proto(verdict: proto::enterprise::firewall::FirewallPolicy) -> Self {
        match verdict {
            proto::enterprise::firewall::FirewallPolicy::Allow => Self::Allow,
            proto::enterprise::firewall::FirewallPolicy::Deny => Self::Deny,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct FirewallRule {
    pub comment: Option<String>,
    pub destination_addrs: Vec<Address>,
    pub destination_ports: Vec<Port>,
    pub id: i64,
    pub verdict: Policy,
    pub protocols: Vec<Protocol>,
    pub source_addrs: Vec<Address>,
    /// Whether a rule uses IPv4 (true) or IPv6 (false)
    pub ipv4: bool, // FIXME: is that really needed?
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct FirewallConfig {
    pub rules: Vec<FirewallRule>,
    pub default_policy: Policy,
}

impl FirewallConfig {
    pub fn from_proto(
        config: proto::enterprise::firewall::FirewallConfig,
    ) -> Result<Self, FirewallError> {
        debug!("Parsing following received firewall proto configuration: {config:?}");
        let mut rules = Vec::new();
        let default_policy =
            Policy::from_proto(config.default_policy.try_into().map_err(|err| {
                FirewallError::TypeConversionError(format!("Invalid default policy: {err:?}"))
            })?);
        debug!(
            "Default firewall policy defined: {default_policy:?}. Proceeding to parsing rules..."
        );

        for rule in config.rules {
            debug!("Parsing the following received Defguard ACL proto rule: {rule:?}");
            let mut source_addrs = Vec::new();
            let mut destination_addrs = Vec::new();
            let mut destination_ports = Vec::new();
            let mut protocols = Vec::new();

            for addr in rule.source_addrs {
                source_addrs.push(Address::from_proto(&addr)?);
            }

            for addr in rule.destination_addrs {
                destination_addrs.push(Address::from_proto(&addr)?);
            }

            for port in rule.destination_ports {
                destination_ports.push(Port::from_proto(&port)?);
            }

            for protocol in rule.protocols {
                protocols.push(Protocol::from_proto(
                    // Since the protocol is an i32, convert it to the proto enum variant first
                    proto::enterprise::firewall::Protocol::try_from(protocol).map_err(|err| {
                        FirewallError::TypeConversionError(format!(
                            "Invalid protocol: {protocol:?}. Details: {err:?}",
                        ))
                    })?,
                )?);
            }

            let verdict = Policy::from_proto(rule.verdict.try_into().map_err(|err| {
                FirewallError::TypeConversionError(format!("Invalid rule verdict: {err:?}"))
            })?);

            let ipv4 = rule.ip_version == proto::enterprise::firewall::IpVersion::Ipv4 as i32;
            let firewall_rule = FirewallRule {
                id: rule.id,
                source_addrs,
                destination_addrs,
                destination_ports,
                protocols,
                verdict,
                ipv4,
                comment: rule.comment,
            };

            debug!("Parsed received proto rule as: {firewall_rule:?}");

            rules.push(firewall_rule);
        }

        Ok(Self {
            rules,
            default_policy,
        })
    }
}

#[derive(Debug, Error)]
pub enum FirewallError {
    #[error("IP address range: {0}")]
    IpAddrRange(#[from] IpAddrRangeError),
    #[error("Io error: {0}")]
    Io(#[from] std::io::Error),
    #[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "netbsd"))]
    #[error("Errno:{0}")]
    Errno(#[from] nix::errno::Errno),
    #[error("Type conversion error: {0}")]
    TypeConversionError(String),
    #[error("Out of memory: {0}")]
    OutOfMemory(String),
    #[error("Unsupported protocol: {0}")]
    UnsupportedProtocol(u8),
    #[cfg(target_os = "linux")]
    #[error("Netlink error: {0}")]
    NetlinkError(String),
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),
    #[error(
        "Firewall transaction not started. Start the firewall transaction first in order to \
        interact with the firewall API."
    )]
    TransactionNotStarted,
    #[error("Firewall transaction failed: {0}")]
    TransactionFailed(String),
}
