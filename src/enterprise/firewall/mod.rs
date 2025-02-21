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
