use std::{net::IpAddr, str::FromStr};

use ipnetwork::IpNetwork;
use thiserror::Error;

use crate::proto;

pub mod api;
#[cfg(target_os = "linux")]
pub mod linux;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Address {
    Ip(IpAddr),
    Network(IpNetwork),
    Range(IpAddr, IpAddr),
}

impl Address {
    pub fn from_proto(ip: &proto::enterprise::firewall::IpAddress) -> Result<Self, FirewallError> {
        match &ip.address {
            Some(proto::enterprise::firewall::ip_address::Address::Ip(ip)) => {
                Ok(Self::Ip(IpAddr::from_str(ip).map_err(|err| {
                    FirewallError::TypeConversionError(format!("Invalid IP format: {}", err))
                })?))
            }
            Some(proto::enterprise::firewall::ip_address::Address::IpSubnet(network)) => Ok(
                Self::Network(IpNetwork::from_str(network).map_err(|err| {
                    FirewallError::TypeConversionError(format!("Invalid subnet format: {}", err))
                })?),
            ),
            Some(proto::enterprise::firewall::ip_address::Address::IpRange(range)) => {
                let start = IpAddr::from_str(&range.start).map_err(|err| {
                    FirewallError::TypeConversionError(format!("Invalid IP format: {}", err))
                })?;
                let end = IpAddr::from_str(&range.end).map_err(|err| {
                    FirewallError::TypeConversionError(format!("Invalid IP format: {}", err))
                })?;
                Ok(Self::Range(start, end))
            }
            _ => Err(FirewallError::TypeConversionError(format!(
                "Invalid IP address type. Must be one of Ip, IpSubnet, IpRange. Instead got {:?}",
                ip.address
            ))),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Port {
    Single(u16),
    Range(u16, u16),
}

impl Port {
    pub fn from_proto(port: &proto::enterprise::firewall::Port) -> Result<Self, FirewallError> {
        match &port.port {
            Some(proto::enterprise::firewall::port::Port::SinglePort(port)) => {
                let port_u16 = u16::try_from(*port).map_err(|err| {
                    FirewallError::TypeConversionError(format!(
                        "Invalid port number ({}): {}",
                        port, err
                    ))
                })?;
                Ok(Self::Single(port_u16))
            }
            Some(proto::enterprise::firewall::port::Port::PortRange(range)) => {
                let start_u16 = u16::try_from(range.start).map_err(|err| {
                    FirewallError::TypeConversionError(format!(
                        "Invalid range start port number ({}): {}",
                        range.start, err
                    ))
                })?;
                let end_u16 = u16::try_from(range.end).map_err(|err| {
                    FirewallError::TypeConversionError(format!(
                        "Invalid range end port number ({}): {}",
                        range.end, err
                    ))
                })?;
                Ok(Self::Range(start_u16, end_u16))
            }
            _ => Err(FirewallError::TypeConversionError(format!(
                "Invalid port type. Must be one of SinglePort, PortRange. Instead got: {:?}",
                port.port
            ))),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Protocol(pub u8);

// Protocols that have the concept of ports
pub const PORT_PROTOCOLS: [Protocol; 2] = [
    // TCP
    Protocol(6),
    // UDP
    Protocol(17),
];

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    Allow,
    Deny,
    #[default]
    None,
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
    pub const fn from_proto(verdict: proto::enterprise::firewall::FirewallPolicy) -> Self {
        match verdict {
            proto::enterprise::firewall::FirewallPolicy::Allow => Self::Allow,
            proto::enterprise::firewall::FirewallPolicy::Deny => Self::Deny,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallRule {
    pub comment: Option<String>,
    pub destination_addrs: Vec<Address>,
    pub destination_ports: Vec<Port>,
    pub id: i64,
    pub verdict: Policy,
    pub protocols: Vec<Protocol>,
    pub source_addrs: Vec<Address>,
    pub v4: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallConfig {
    pub rules: Vec<FirewallRule>,
    pub default_policy: Policy,
    pub v4: bool,
}

impl FirewallConfig {
    pub fn from_proto(
        config: proto::enterprise::firewall::FirewallConfig,
    ) -> Result<Self, FirewallError> {
        debug!("Parsing following received firewall proto configuration: {config:?}");
        let mut rules = vec![];
        let v4 = config.ip_version == proto::enterprise::firewall::IpVersion::Ipv4 as i32;
        let default_policy =
            Policy::from_proto(config.default_policy.try_into().map_err(|err| {
                FirewallError::TypeConversionError(format!("Invalid default policy: {:?}", err))
            })?);
        debug!("Using IPv4: {v4:?}, default firewall policy defined: {default_policy:?}. Proceeding to parsing rules...");

        for rule in config.rules {
            debug!("Parsing the following received Defguard ACL proto rule: {rule:?}");
            let mut source_addrs = vec![];
            let mut destination_addrs = vec![];
            let mut destination_ports = vec![];
            let mut protocols = vec![];

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
                            "Invalid protocol: {:?}. Details: {:?}",
                            protocol, err
                        ))
                    })?,
                )?);
            }

            let verdict = Policy::from_proto(rule.verdict.try_into().map_err(|err| {
                FirewallError::TypeConversionError(format!("Invalid rule verdict: {:?}", err))
            })?);

            let firewall_rule = FirewallRule {
                id: rule.id,
                source_addrs,
                destination_addrs,
                destination_ports,
                protocols,
                verdict,
                v4,
                comment: rule.comment,
            };

            debug!("Parsed received proto rule as: {firewall_rule:?}");

            rules.push(firewall_rule);
        }

        Ok(Self {
            rules,
            default_policy,
            v4,
        })
    }
}

#[derive(Debug, Error)]
pub enum FirewallError {
    #[error("Type conversion error: {0}")]
    TypeConversionError(String),
    #[error("Out of memory: {0}")]
    OutOfMemory(String),
    #[error("Unsupported protocol: {0}")]
    UnsupportedProtocol(u8),
    #[error("Netlink error: {0}")]
    NetlinkError(String),
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),
}
