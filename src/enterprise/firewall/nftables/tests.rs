use std::{cmp::Ordering, str::FromStr};

use ipnetwork::IpNetwork;

use super::*;

#[test]
fn test_sorting() {
    let mut addrs = vec![
        Address::Network(IpNetwork::from_str("10.10.10.11/24").unwrap()),
        Address::Network(IpNetwork::from_str("10.10.10.12/24").unwrap()),
        Address::Network(IpNetwork::from_str("10.10.11.10/32").unwrap()),
        Address::Network(IpNetwork::from_str("10.10.11.11/32").unwrap()),
        Address::Network(IpNetwork::from_str("10.10.10.10/24").unwrap()),
        Address::Network(IpNetwork::from_str("10.10.11.12/32").unwrap()),
    ];

    addrs.sort_by(|a, b| a.first().partial_cmp(&b.first()).unwrap_or(Ordering::Equal));

    assert_eq!(
        addrs,
        vec![
            Address::Network(IpNetwork::from_str("10.10.10.10/24").unwrap()),
            Address::Network(IpNetwork::from_str("10.10.10.11/24").unwrap()),
            Address::Network(IpNetwork::from_str("10.10.10.12/24").unwrap()),
            Address::Network(IpNetwork::from_str("10.10.11.10/32").unwrap()),
            Address::Network(IpNetwork::from_str("10.10.11.11/32").unwrap()),
            Address::Network(IpNetwork::from_str("10.10.11.12/32").unwrap()),
        ]
    );

    let _prepared_addrs = merge_addrs(addrs).unwrap();
}

#[test]
fn test_merge_addrs_empty() {
    let addrs = Vec::new();
    let result = merge_addrs(addrs).unwrap();
    assert!(result.is_empty());
}

#[test]
fn test_merge_addrs_single_address() {
    let addrs = vec![Address::Network(
        IpNetwork::from_str("192.168.1.10/32").unwrap(),
    )];
    let result = merge_addrs(addrs.clone()).unwrap();

    assert_eq!(result, addrs);
}

#[test]
fn test_merge_addrs_adjacent_ranges() {
    let addrs = vec![
        Address::Range(
            IpAddrRange::new(
                IpAddr::from_str("192.168.1.10").unwrap(),
                IpAddr::from_str("192.168.1.20").unwrap(),
            )
            .unwrap(),
        ),
        Address::Range(
            IpAddrRange::new(
                IpAddr::from_str("192.168.1.21").unwrap(),
                IpAddr::from_str("192.168.1.30").unwrap(),
            )
            .unwrap(),
        ),
    ];
    let result = merge_addrs(addrs).unwrap();

    assert_eq!(result.len(), 1);
    if let Address::Range(range) = &result[0] {
        assert_eq!(range.start(), IpAddr::from_str("192.168.1.10").unwrap());
        assert_eq!(range.end(), IpAddr::from_str("192.168.1.30").unwrap());
    } else {
        panic!("Expected Address::Range");
    }
}

#[test]
fn test_merge_addrs_adjacent_single_addresses() {
    let addrs = vec![
        Address::Network(IpNetwork::from_str("192.168.1.10/32").unwrap()),
        Address::Network(IpNetwork::from_str("192.168.1.11/32").unwrap()),
        Address::Network(IpNetwork::from_str("192.168.1.12/32").unwrap()),
    ];
    let result = merge_addrs(addrs).unwrap();

    assert_eq!(result.len(), 1);
    if let Address::Range(range) = &result[0] {
        assert_eq!(range.start(), IpAddr::from_str("192.168.1.10").unwrap());
        assert_eq!(range.end(), IpAddr::from_str("192.168.1.12").unwrap());
    } else {
        panic!("Expected Address::Range");
    }
}

#[test]
fn test_merge_addrs_non_adjacent_ranges() {
    let addrs = vec![
        Address::Range(
            IpAddrRange::new(
                IpAddr::from_str("192.168.1.10").unwrap(),
                IpAddr::from_str("192.168.1.20").unwrap(),
            )
            .unwrap(),
        ),
        Address::Range(
            IpAddrRange::new(
                IpAddr::from_str("192.168.1.30").unwrap(),
                IpAddr::from_str("192.168.1.40").unwrap(),
            )
            .unwrap(),
        ),
    ];
    let result = merge_addrs(addrs).unwrap();

    assert_eq!(result.len(), 2);
    if let Address::Range(range1) = &result[0] {
        assert_eq!(range1.start(), IpAddr::from_str("192.168.1.10").unwrap());
        assert_eq!(range1.end(), IpAddr::from_str("192.168.1.20").unwrap());
    } else {
        panic!("Expected Address::Range");
    }
    if let Address::Range(range2) = &result[1] {
        assert_eq!(range2.start(), IpAddr::from_str("192.168.1.30").unwrap());
        assert_eq!(range2.end(), IpAddr::from_str("192.168.1.40").unwrap());
    } else {
        panic!("Expected Address::Range");
    }
}

#[test]
fn test_merge_addrs_mixed_networks_and_ranges() {
    let addrs = vec![
        Address::Network(IpNetwork::from_str("192.168.1.10/32").unwrap()),
        Address::Range(
            IpAddrRange::new(
                IpAddr::from_str("192.168.1.11").unwrap(),
                IpAddr::from_str("192.168.1.15").unwrap(),
            )
            .unwrap(),
        ),
        Address::Network(IpNetwork::from_str("192.168.1.16/32").unwrap()),
    ];
    let result = merge_addrs(addrs).unwrap();

    assert_eq!(result.len(), 1);
    if let Address::Range(range) = &result[0] {
        assert_eq!(range.start(), IpAddr::from_str("192.168.1.10").unwrap());
        assert_eq!(range.end(), IpAddr::from_str("192.168.1.16").unwrap());
    } else {
        panic!("Expected Address::Range");
    }
}

#[test]
fn test_merge_addrs_non_adjacent_singles() {
    let addrs = vec![
        Address::Network(IpNetwork::from_str("192.168.1.10/32").unwrap()),
        Address::Network(IpNetwork::from_str("192.168.1.11/32").unwrap()),
        Address::Network(IpNetwork::from_str("192.168.1.15/32").unwrap()),
        Address::Network(IpNetwork::from_str("192.168.1.20/32").unwrap()),
    ];
    let result = merge_addrs(addrs).unwrap();

    // These should result in 3 separate ranges: 10-11, 15, 20
    let expected_addrs = vec![
        Address::Range(
            IpAddrRange::new(
                IpAddr::from_str("192.168.1.10").unwrap(),
                IpAddr::from_str("192.168.1.11").unwrap(),
            )
            .unwrap(),
        ),
        Address::Network(IpNetwork::from_str("192.168.1.15/32").unwrap()),
        Address::Network(IpNetwork::from_str("192.168.1.20/32").unwrap()),
    ];
    assert_eq!(result, expected_addrs);
}

#[test]
fn test_merge_addrs_ipv6() {
    let addrs = vec![
        Address::Network(IpNetwork::from_str("2001:db8::1/128").unwrap()),
        Address::Network(IpNetwork::from_str("2001:db8::2/128").unwrap()),
        Address::Network(IpNetwork::from_str("2001:db8::3/128").unwrap()),
    ];
    let result = merge_addrs(addrs).unwrap();

    assert_eq!(result.len(), 1);
    if let Address::Range(range) = &result[0] {
        assert_eq!(range.start(), IpAddr::from_str("2001:db8::1").unwrap());
        assert_eq!(range.end(), IpAddr::from_str("2001:db8::3").unwrap());
    } else {
        panic!("Expected Address::Range");
    }
}

#[test]
fn test_next_ip_ipv4() {
    assert_eq!(
        next_ip(IpAddr::from_str("192.168.1.10").unwrap()),
        IpAddr::from_str("192.168.1.11").unwrap()
    );

    // Test overflow
    assert_eq!(
        next_ip(IpAddr::from_str("255.255.255.255").unwrap()),
        IpAddr::from_str("0.0.0.0").unwrap()
    );
}

#[test]
fn test_next_ip_ipv6() {
    assert_eq!(
        next_ip(IpAddr::from_str("2001:db8::1").unwrap()),
        IpAddr::from_str("2001:db8::2").unwrap()
    );

    // Test overflow
    assert_eq!(
        next_ip(IpAddr::from_str("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff").unwrap()),
        IpAddr::from_str("::").unwrap()
    );
}

#[test]
fn test_merge_addrs_gap() {
    let addrs = vec![
        Address::Network(IpNetwork::from_str("192.168.1.1/32").unwrap()),
        Address::Network(IpNetwork::from_str("192.168.1.100/32").unwrap()),
    ];
    let result = merge_addrs(addrs.clone()).unwrap();

    // Should not merge since there's a gap
    assert_eq!(result, addrs);

    let addrs = vec![
        Address::Range(
            IpAddrRange::new(
                IpAddr::from_str("192.168.1.10").unwrap(),
                IpAddr::from_str("192.168.1.20").unwrap(),
            )
            .unwrap(),
        ),
        Address::Network(IpNetwork::from_str("192.168.1.100/32").unwrap()),
    ];
    let result = merge_addrs(addrs.clone()).unwrap();

    // Should not merge since there's a gap
    assert_eq!(result, addrs);
}
