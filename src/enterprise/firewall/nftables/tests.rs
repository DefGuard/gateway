use std::{cmp::Ordering, str::FromStr};

use ipnetwork::IpNetwork;

use super::*;

#[test]
fn test_sorting() {
    let mut addrs = vec![
        Address::Network(IpNetwork::V4(
            Ipv4Network::new(Ipv4Addr::new(10, 10, 10, 11), 24).unwrap(),
        )),
        Address::Network(IpNetwork::V4(
            Ipv4Network::new(Ipv4Addr::new(10, 10, 10, 12), 24).unwrap(),
        )),
        Address::Network(IpNetwork::V4(
            Ipv4Network::new(Ipv4Addr::new(10, 10, 11, 10), 32).unwrap(),
        )),
        Address::Network(IpNetwork::V4(
            Ipv4Network::new(Ipv4Addr::new(10, 10, 11, 11), 32).unwrap(),
        )),
        Address::Network(IpNetwork::V4(
            Ipv4Network::new(Ipv4Addr::new(10, 10, 10, 10), 24).unwrap(),
        )),
        Address::Network(IpNetwork::V4(
            Ipv4Network::new(Ipv4Addr::new(10, 10, 11, 12), 32).unwrap(),
        )),
    ];

    addrs.sort_by(|a, b| a.first().partial_cmp(&b.first()).unwrap_or(Ordering::Equal));

    assert_eq!(
        addrs,
        vec![
            Address::Network(IpNetwork::V4(
                Ipv4Network::new(Ipv4Addr::new(10, 10, 10, 10), 24).unwrap(),
            )),
            Address::Network(IpNetwork::V4(
                Ipv4Network::new(Ipv4Addr::new(10, 10, 10, 11), 24).unwrap(),
            )),
            Address::Network(IpNetwork::V4(
                Ipv4Network::new(Ipv4Addr::new(10, 10, 10, 12), 24).unwrap(),
            )),
            Address::Network(IpNetwork::V4(
                Ipv4Network::new(Ipv4Addr::new(10, 10, 11, 10), 32).unwrap(),
            )),
            Address::Network(IpNetwork::V4(
                Ipv4Network::new(Ipv4Addr::new(10, 10, 11, 11), 32).unwrap(),
            )),
            Address::Network(IpNetwork::V4(
                Ipv4Network::new(Ipv4Addr::new(10, 10, 11, 12), 32).unwrap(),
            )),
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
        IpNetwork::V4(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 32).unwrap(),
    )];
    let result = merge_addrs(addrs.clone()).unwrap();

    assert_eq!(result, addrs);
}

#[test]
fn test_merge_addrs_adjacent_ranges() {
    let addrs = vec![
        Address::Range(
            IpAddrRange::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
            )
            .unwrap(),
        ),
        Address::Range(
            IpAddrRange::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 21)),
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 30)),
            )
            .unwrap(),
        ),
    ];
    let result = merge_addrs(addrs).unwrap();

    assert_eq!(result.len(), 1);
    if let Address::Range(range) = &result[0] {
        assert_eq!(range.start(), IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)));
        assert_eq!(range.end(), IpAddr::V4(Ipv4Addr::new(192, 168, 1, 30)));
    } else {
        panic!("Expected Address::Range");
    }
}

#[test]
fn test_merge_addrs_adjacent_single_addresses() {
    let addrs = vec![
        Address::Network(IpNetwork::V4(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 32).unwrap()),
        Address::Network(IpNetwork::V4(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 11)), 32).unwrap()),
        Address::Network(IpNetwork::V4(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 12)), 32).unwrap()),
    ];
    let result = merge_addrs(addrs).unwrap();

    assert_eq!(result.len(), 1);
    if let Address::Range(range) = &result[0] {
        assert_eq!(range.start(), IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)));
        assert_eq!(range.end(), IpAddr::V4(Ipv4Addr::new(192, 168, 1, 12)));
    } else {
        panic!("Expected Address::Range");
    }
}

#[test]
fn test_merge_addrs_non_adjacent_ranges() {
    let addrs = vec![
        Address::Range(
            IpAddrRange::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
            )
            .unwrap(),
        ),
        Address::Range(
            IpAddrRange::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 30)),
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 40)),
            )
            .unwrap(),
        ),
    ];
    let result = merge_addrs(addrs).unwrap();

    assert_eq!(result.len(), 2);
    if let Address::Range(range1) = &result[0] {
        assert_eq!(range1.start(), IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)));
        assert_eq!(range1.end(), IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)));
    } else {
        panic!("Expected Address::Range");
    }
    if let Address::Range(range2) = &result[1] {
        assert_eq!(range2.start(), IpAddr::V4(Ipv4Addr::new(192, 168, 1, 30)));
        assert_eq!(range2.end(), IpAddr::V4(Ipv4Addr::new(192, 168, 1, 40)));
    } else {
        panic!("Expected Address::Range");
    }
}

#[test]
fn test_merge_addrs_mixed_networks_and_ranges() {
    let addrs = vec![
        Address::Network(IpNetwork::V4(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 32).unwrap()),
        Address::Range(
            IpAddrRange::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 11)),
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 15)),
            )
            .unwrap(),
        ),
        Address::Network(IpNetwork::V4(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 16)), 32).unwrap()),
    ];
    let result = merge_addrs(addrs).unwrap();

    assert_eq!(result.len(), 1);
    if let Address::Range(range) = &result[0] {
        assert_eq!(range.start(), IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)));
        assert_eq!(range.end(), IpAddr::V4(Ipv4Addr::new(192, 168, 1, 16)));
    } else {
        panic!("Expected Address::Range");
    }
}

#[test]
fn test_merge_addrs_non_adjacent_singles() {
    let addrs = vec![
        Address::Network(IpNetwork::V4(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 32).unwrap()),
        Address::Network(IpNetwork::V4(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 11)), 32).unwrap()),
        Address::Network(IpNetwork::V4(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 15)), 32).unwrap()),
        Address::Network(IpNetwork::V4(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)), 32).unwrap()),
    ];
    let result = merge_addrs(addrs).unwrap();

    // These should result in 3 separate ranges: 10-11, 15, 20
    let expected_addrs = vec![
        Address::Range(
            IpAddrRange::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 11)),
            )
            .unwrap(),
        ),
        Address::Network(IpNetwork::V4(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 15)), 32).unwrap()),
        Address::Network(IpNetwork::V4(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)), 32).unwrap()),
    ];
    assert_eq!(result, expected_addrs);
}

#[test]
fn test_merge_addrs_ipv6() {
    let addrs = vec![
        Address::Network(
            IpNetwork::V6(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)),
                128,
            )
            .unwrap(),
        ),
        Address::Network(
            IpNetwork::V6(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 2)),
                128,
            )
            .unwrap(),
        ),
        Address::Network(
            IpNetwork::V6(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 3)),
                128,
            )
            .unwrap(),
        ),
    ];
    let result = merge_addrs(addrs).unwrap();

    assert_eq!(result.len(), 1);
    if let Address::Range(range) = &result[0] {
        assert_eq!(
            range.start(),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1))
        );
        assert_eq!(
            range.end(),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 3))
        );
    } else {
        panic!("Expected Address::Range");
    }
}

#[test]
fn test_next_ip_ipv4() {
    assert_eq!(
        next_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))),
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 11))
    );

    // Test overflow
    assert_eq!(
        next_ip(IpAddr::V4(Ipv4Addr::BROADCAST)),
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    );
}

#[test]
fn test_next_ip_ipv6() {
    assert_eq!(
        next_ip(IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1))),
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 2))
    );

    // Test overflow
    assert_eq!(
        next_ip(IpAddr::V6(Ipv6Addr::new(
            0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff
        ))),
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    );
}

#[test]
fn test_merge_addrs_gap() {
    let addrs = vec![
        Address::Network(IpNetwork::V4(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 32).unwrap()),
        Address::Network(IpNetwork::V4(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 32).unwrap()),
    ];
    let result = merge_addrs(addrs.clone()).unwrap();

    // Should not merge since there's a gap
    assert_eq!(result, addrs);

    let addrs = vec![
        Address::Range(
            IpAddrRange::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
            )
            .unwrap(),
        ),
        Address::Network(IpNetwork::V4(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 32).unwrap()),
    ];
    let result = merge_addrs(addrs.clone()).unwrap();

    // Should not merge since there's a gap
    assert_eq!(result, addrs);
}
