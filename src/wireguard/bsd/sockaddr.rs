use std::{
    mem::size_of,
    net::{IpAddr, SocketAddr},
};

use super::cast_ref;

/// Covert binary `sockaddr_in` or `sockaddr_in6` (see netinet/in.h) to `SocketAddr`.
/// Only AF_INET (IPv4) and AF_INET6 (IPv6) addresses are supported.

// netinet/in.h
#[repr(C)]
struct SockAddrIn {
    len: u8,
    family: u8,
    port: u16,
    addr: [u8; 4],
    _zero: [u8; 8],
}

impl From<&SockAddrIn> for SocketAddr {
    fn from(sa: &SockAddrIn) -> SocketAddr {
        SocketAddr::new(IpAddr::from(sa.addr), u16::from_be(sa.port))
    }
}

// netinet6/in6.h
#[repr(C)]
struct SockAddrIn6 {
    len: u8,
    family: u8,
    port: u16,
    flowinfo: u32,
    addr: [u8; 16],
    scope_id: u32,
}

impl From<&SockAddrIn6> for SocketAddr {
    fn from(sa: &SockAddrIn6) -> SocketAddr {
        SocketAddr::new(IpAddr::from(sa.addr), u16::from_be(sa.port))
    }
}

pub(super) fn unpack_sockaddr(buf: &[u8]) -> Option<SocketAddr> {
    const AF_INET: u8 = 2;
    const AF_INET6: u8 = 30;

    const SA_IN_SIZE: usize = size_of::<SockAddrIn>();
    const SA_IN6_SIZE: usize = size_of::<SockAddrIn6>();

    match buf.len() {
        SA_IN_SIZE => {
            let sockaddr_in = unsafe { cast_ref::<SockAddrIn>(buf) };
            // sanity checks
            if sockaddr_in.len == SA_IN_SIZE as u8 && sockaddr_in.family == AF_INET {
                Some(sockaddr_in.into())
            } else {
                None
            }
        }

        SA_IN6_SIZE => {
            let sockaddr_in6 = unsafe { cast_ref::<SockAddrIn6>(buf) };
            // sanity checks
            if sockaddr_in6.len == SA_IN6_SIZE as u8 && sockaddr_in6.family == AF_INET6 {
                Some(sockaddr_in6.into())
            } else {
                None
            }
        }

        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn ip4() {
        let buf = [16, 2, 28, 133, 192, 168, 12, 34, 0, 0, 0, 0, 0, 0, 0, 0];
        let addr = unpack_sockaddr(&buf).unwrap();
        assert_eq!(addr.port(), 7301);
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(192, 168, 12, 34)));
    }

    #[test]
    fn ip6() {
        let buf = [
            28, 30, 28, 133, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 192, 168, 12, 34,
            0, 0, 0, 0,
        ];
        let addr = unpack_sockaddr(&buf).unwrap();
        assert_eq!(addr.port(), 7301);
        assert_eq!(
            addr.ip(),
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc0a8, 0x0c22))
        );
    }
}
