pub mod api;
#[cfg(test)]
mod dummy;
mod iprange;
#[cfg(all(not(test), target_os = "linux"))]
mod nftables;
#[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "netbsd"))]
mod packetfilter;

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use iprange::{IpAddrRange, IpAddrRangeError};
use thiserror::Error;

use crate::proto;

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Address {
    Network(IpNetwork),
    Range(IpAddrRange),
}

impl Address {
    // FIXME: remove after merging nft hotfix into dev
    #[allow(dead_code)]
    pub fn first(&self) -> IpAddr {
        match self {
            Address::Network(network) => network.ip(),
            Address::Range(range) => range.start(),
        }
    }

    // FIXME: remove after merging nft hotfix into dev
    #[allow(dead_code)]
    pub fn last(&self) -> IpAddr {
        match self {
            Address::Network(network) => max_address(network),
            Address::Range(range) => range.end(),
        }
    }

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

#[allow(dead_code)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub(crate) enum Port {
    Any,
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
#[allow(dead_code)]
#[derive(Debug, Copy, Clone, PartialEq)]
#[repr(u8)]
pub(crate) enum Protocol {
    Any = libc::IPPROTO_IP as u8,
    Icmp = libc::IPPROTO_ICMP as u8,
    Tcp = libc::IPPROTO_TCP as u8,
    Udp = libc::IPPROTO_UDP as u8,
    IcmpV6 = libc::IPPROTO_ICMPV6 as u8,
}

#[allow(dead_code)]
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
            // Add implicit unspecified address to pin it to a specific IP version.
            if source_addrs.is_empty() {
                source_addrs.push(if ipv4 {
                    Address::Network(IpNetwork::V4(
                        Ipv4Network::new(Ipv4Addr::UNSPECIFIED, 0).unwrap(),
                    ))
                } else {
                    Address::Network(IpNetwork::V6(
                        Ipv6Network::new(Ipv6Addr::UNSPECIFIED, 0).unwrap(),
                    ))
                });
            }
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

/// Get the max address in a network.
///
/// - In IPv4 this is the broadcast address.
/// - In IPv6 this is just the last address in the network.
pub fn max_address(network: &IpNetwork) -> IpAddr {
    match network {
        IpNetwork::V4(network) => {
            let addr = network.ip().to_bits();
            let mask = network.mask().to_bits();

            IpAddr::V4(Ipv4Addr::from(addr | !mask))
        }
        IpNetwork::V6(network) => {
            let addr = network.ip().to_bits();
            let mask = network.mask().to_bits();

            IpAddr::V6(Ipv6Addr::from(addr | !mask))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_max_address_ipv4_24() {
        let network = IpNetwork::V4(Ipv4Network::from_str("192.168.1.0/24").unwrap());
        let max = max_address(&network);
        assert_eq!(max, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 255)));
    }

    #[test]
    fn test_max_address_ipv4_16() {
        let network = IpNetwork::V4(Ipv4Network::from_str("10.1.0.0/16").unwrap());
        let max = max_address(&network);
        assert_eq!(max, IpAddr::V4(Ipv4Addr::new(10, 1, 255, 255)));
    }

    #[test]
    fn test_max_address_ipv4_8() {
        let network = IpNetwork::V4(Ipv4Network::from_str("172.16.0.0/8").unwrap());
        let max = max_address(&network);
        assert_eq!(max, IpAddr::V4(Ipv4Addr::new(172, 255, 255, 255)));
    }

    #[test]
    fn test_max_address_ipv4_32() {
        let network = IpNetwork::V4(Ipv4Network::from_str("192.168.1.1/32").unwrap());
        let max = max_address(&network);
        assert_eq!(max, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn test_max_address_ipv6_64() {
        let network = IpNetwork::V6(Ipv6Network::from_str("2001:db8::/64").unwrap());
        let max = max_address(&network);
        assert_eq!(
            max,
            IpAddr::V6(Ipv6Addr::from_str("2001:db8::ffff:ffff:ffff:ffff").unwrap())
        );
    }

    #[test]
    fn test_max_address_ipv6_128() {
        let network = IpNetwork::V6(Ipv6Network::from_str("2001:db8::1/128").unwrap());
        let max = max_address(&network);
        assert_eq!(max, IpAddr::V6(Ipv6Addr::from_str("2001:db8::1").unwrap()));
    }

    #[test]
    fn test_max_address_ipv6_48() {
        let network = IpNetwork::V6(Ipv6Network::from_str("2001:db8:1234::/48").unwrap());
        let max = max_address(&network);
        assert_eq!(
            max,
            IpAddr::V6(Ipv6Addr::from_str("2001:db8:1234:ffff:ffff:ffff:ffff:ffff").unwrap())
        );
    }
}
