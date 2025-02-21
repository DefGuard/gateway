use std::{net::IpAddr, str::FromStr};

use ipnetwork::IpNetwork;

use crate::proto;

pub mod api;
#[cfg(target_os = "linux")]
pub mod linux;

#[derive(Debug, Copy, Clone)]
pub enum Address {
    Ip(IpAddr),
    Network(IpNetwork),
    Range(IpAddr, IpAddr),
}

impl TryFrom<&proto::enterprise::IpAddress> for Address {
    type Error = &'static str;

    fn try_from(ip: &proto::enterprise::IpAddress) -> Result<Self, Self::Error> {
        match &ip.address {
            Some(proto::enterprise::ip_address::Address::Ip(ip)) => Ok(Self::Ip(
                IpAddr::from_str(ip).map_err(|_| "Invalid IP format")?,
            )),
            Some(proto::enterprise::ip_address::Address::IpSubnet(network)) => {
                Ok(Self::Network(IpNetwork::from_str(network).unwrap()))
            }
            Some(proto::enterprise::ip_address::Address::IpRange(range)) => {
                let start = IpAddr::from_str(&range.start).unwrap();
                let end = IpAddr::from_str(&range.end).unwrap();
                Ok(Self::Range(start, end))
            }
            _ => Err("Invalid address"),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum Port {
    Single(u16),
    Range(u16, u16),
}

impl From<&proto::enterprise::Port> for Port {
    fn from(port: &proto::enterprise::Port) -> Self {
        match &port.port {
            Some(proto::enterprise::port::Port::SinglePort(port)) => {
                Self::Single(u16::try_from(*port).unwrap())
            }
            Some(proto::enterprise::port::Port::PortRange(range)) => Self::Range(
                u16::try_from(range.start).unwrap(),
                u16::try_from(range.end).unwrap(),
            ),
            _ => panic!("Invalid port"),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct Protocol(pub u8);

pub struct FirewallRule {
    pub id: u32,
    pub source_addrs: Vec<Address>,
    pub destination_addrs: Vec<Address>,
    pub destination_ports: Vec<Port>,
    pub protocols: Vec<Protocol>,
    pub allow: bool,
    pub v4: bool,
    pub comment: Option<String>,
}

pub struct FirewallConfig {
    pub rules: Vec<FirewallRule>,
    pub default_action: bool,
}

impl From<proto::enterprise::FirewallConfig> for FirewallConfig {
    fn from(config: proto::enterprise::FirewallConfig) -> Self {
        let rules = config
            .rules
            .into_iter()
            .map(|rule| FirewallRule {
                // FIXME: Do something else here
                id: rule.id as u32,
                source_addrs: rule
                    .source_addr
                    .into_iter()
                    .map(|addr| Address::try_from(&addr).unwrap())
                    .collect(),
                destination_addrs: rule
                    .destination_addr
                    .into_iter()
                    .map(|addr| Address::try_from(&addr).unwrap())
                    .collect(),
                destination_ports: rule
                    .destination_port
                    .into_iter()
                    .map(|port| Port::from(&port))
                    .collect(),
                protocols: rule
                    .protocol
                    .into_iter()
                    .map(|proto| {
                        proto::enterprise::Protocol::try_from(proto)
                            .unwrap_or_else(|_| {
                                panic!("Unsupported protocol: {:?}", proto);
                            })
                            .into()
                    })
                    .collect(),
                allow: rule.verdict == proto::enterprise::FirewallPolicy::Allow as i32,
                v4: config.ip_version == proto::enterprise::IpVersion::Ipv4 as i32,
                comment: rule.comment,
            })
            .collect();

        Self {
            rules,
            default_action: config.default_policy
                == proto::enterprise::FirewallPolicy::Allow as i32,
        }
    }
}
