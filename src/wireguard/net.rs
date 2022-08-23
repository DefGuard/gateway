#[cfg(target_os = "linux")]
use netlink_packet_wireguard::{
    constants::{AF_INET, AF_INET6},
    nlas::{WgAllowedIp, WgAllowedIpAttrs},
};
use std::{fmt, net::IpAddr, str::FromStr};

#[derive(Debug, PartialEq)]
pub struct IpAddrMask {
    // IP v4 or v6
    pub ip: IpAddr,
    // Classless Inter-Domain Routing
    pub cidr: u8,
}

impl IpAddrMask {
    #[must_use]
    pub fn new(ip: IpAddr, cidr: u8) -> Self {
        Self { ip, cidr }
    }

    #[cfg(target_os = "linux")]
    pub fn to_nlas_allowed_ip(&self) -> WgAllowedIp {
        let mut attrs = Vec::new();
        attrs.push(WgAllowedIpAttrs::Family(if self.ip.is_ipv4() {
            AF_INET
        } else {
            AF_INET6
        }));
        attrs.push(WgAllowedIpAttrs::IpAddr(self.ip));
        attrs.push(WgAllowedIpAttrs::Cidr(self.cidr));
        WgAllowedIp(attrs)
    }
}

impl fmt::Display for IpAddrMask {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.ip, self.cidr)
    }
}

impl FromStr for IpAddrMask {
    type Err = ();

    fn from_str(ip_str: &str) -> Result<Self, Self::Err> {
        if let Some((left, right)) = ip_str.split_once('/') {
            Ok(IpAddrMask {
                ip: left.parse().map_err(|_| ())?,
                cidr: right.parse().map_err(|_| ())?,
            })
        } else {
            let ip: IpAddr = ip_str.parse().map_err(|_| ())?;
            Ok(IpAddrMask {
                ip,
                cidr: if ip.is_ipv4() { 32 } else { 128 },
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn parse_ip_addr() {
        let ip: IpAddrMask = "192.168.0.1/24".parse().unwrap();
        assert_eq!(
            ip,
            IpAddrMask::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)), 24)
        );

        let ip: IpAddrMask = "10.11.12.13".parse().unwrap();
        assert_eq!(
            ip,
            IpAddrMask::new(IpAddr::V4(Ipv4Addr::new(10, 11, 12, 13)), 32)
        );

        let ip: IpAddrMask = "2001:0db8::1428:57ab/96".parse().unwrap();
        assert_eq!(
            ip,
            IpAddrMask::new(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0x1428, 0x57ab)),
                96
            )
        );

        let ip: IpAddrMask = "::1".parse().unwrap();
        assert_eq!(
            ip,
            IpAddrMask::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 128)
        );
    }
}
