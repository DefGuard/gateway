//! Range of IP addresses.
//!
//! Encapsulates a range of IP addresses, which can be iterated.
//! For the time being, `RangeInclusive<IpAddr>` can't be used, because `IpAddr` does not implement
//! `Step` trait.

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::RangeInclusive,
};

#[derive(Clone, Debug, PartialEq)]
pub enum IpAddrRange {
    V4(RangeInclusive<Ipv4Addr>),
    V6(RangeInclusive<Ipv6Addr>),
}

#[derive(Debug, thiserror::Error)]
pub enum IpAddrRangeError {
    MixedTypes,
    WrongOrder,
}

impl fmt::Display for IpAddrRangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MixedTypes => write!(f, "mixed IPv4 and IPv6 addresses"),
            Self::WrongOrder => write!(f, "wrong order: higher address preceeds lower"),
        }
    }
}

impl IpAddrRange {
    pub fn new(start: IpAddr, end: IpAddr) -> Result<Self, IpAddrRangeError> {
        if start > end {
            Err(IpAddrRangeError::WrongOrder)
        } else {
            match (start, end) {
                (IpAddr::V4(start), IpAddr::V4(end)) => Ok(Self::V4(start..=end)),
                (IpAddr::V6(start), IpAddr::V6(end)) => Ok(Self::V6(start..=end)),
                _ => Err(IpAddrRangeError::MixedTypes),
            }
        }
    }

    /// Returns `true` if `ipaddr` is contained in the range.
    pub fn contains(&self, ipaddr: &IpAddr) -> bool {
        match self {
            Self::V4(range) => range.contains(ipaddr),
            Self::V6(range) => range.contains(ipaddr),
        }
    }

    /// Returns `true` if the range contains no items.
    pub fn is_empty(&self) -> bool {
        match self {
            Self::V4(range) => range.is_empty(),
            Self::V6(range) => range.is_empty(),
        }
    }

    /// Returns `true` if range contains IPv4 address, and `false` otherwise.
    pub fn is_ipv4(&self) -> bool {
        match self {
            Self::V4(_) => true,
            Self::V6(_) => false,
        }
    }

    /// Returns `true` if range contains IPv6 address, and `false` otherwise.
    pub fn is_ipv6(&self) -> bool {
        match self {
            Self::V4(_) => false,
            Self::V6(_) => true,
        }
    }
}

impl Iterator for IpAddrRange {
    type Item = IpAddr;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::V4(range) => range.next().map(IpAddr::V4),
            Self::V6(range) => range.next().map(IpAddr::V6),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_range() {
        let start = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let end = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3));
        let range = start..=end;

        let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        assert!(range.contains(&addr));

        let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 5));
        assert!(!range.contains(&addr));

        // As of Rust 1.87.0, `IpAddr` does not implement `Step`.
        // assert_eq!(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 5)), range.next());
    }

    #[test]
    fn test_ipaddrrange() {
        let start = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let end = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3));
        let mut range = IpAddrRange::new(start, end).unwrap();

        let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        assert!(range.contains(&addr));

        let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 5));
        assert!(!range.contains(&addr));

        assert_eq!(Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))), range.next());
        assert_eq!(Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))), range.next());
        assert_eq!(Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3))), range.next());
        assert_eq!(None, range.next());
    }
}
