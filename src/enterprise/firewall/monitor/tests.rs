use std::{
    net::{Ipv4Addr, Ipv6Addr},
    time::{Duration, UNIX_EPOCH},
};

use super::*;

#[test]
fn test_connection_event_proto() {
    let event = ConnectionEvent {
        timestamp: UNIX_EPOCH + Duration::from_micros(1_793_198_060_792_864),
        direction: Direction::Inbound,
        status: Status::Blocked,
        protocol: 17,
        source: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        source_port: Some(53),
        destination: IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2)),
        destination_port: None,
        rule_id: None,
        upload_bytes: 0,
        download_bytes: 128,
        count: 1,
    };
    let proto = proto::ConnectionEvent::from(&event);
    let timestamp = proto.timestamp.unwrap();
    assert_eq!(timestamp.seconds, 1_793_198_060);
    assert_eq!(timestamp.nanos, 792_864_000);
    assert_eq!(proto.direction(), proto::Direction::Inbound);
    assert_eq!(proto.status(), proto::Status::Blocked);
    assert_eq!(proto.protocol, 17);
    assert_eq!(proto.source_ip_addr, vec![192, 168, 1, 1]);
    assert_eq!(proto.source_port, Some(53));
    assert_eq!(proto.destination_ip_addr.len(), 16);
    assert_eq!(proto.destination_port, None);
    assert_eq!(proto.rule_id, None);
    assert_eq!(proto.download_bytes, 128);
}

#[test]
fn test_aggregator() {
    let event = |secs, source_port, destination_port, bytes| ConnectionEvent {
        timestamp: UNIX_EPOCH + Duration::from_secs(secs),
        direction: Direction::Outbound,
        status: Status::Allowed,
        protocol: 17,
        source: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        source_port: Some(source_port),
        destination: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        destination_port: Some(destination_port),
        rule_id: None,
        upload_bytes: bytes,
        download_bytes: 2 * bytes,
        count: 1,
    };
    let mut aggregator = Aggregator::default();
    aggregator.add(event(20, 40000, 53, 10));
    aggregator.add(event(10, 40001, 53, 20));
    aggregator.add(event(30, 40002, 123, 30));
    aggregator.add(event(40, 40003, 123, 40));
    aggregator.add(event(5, 40004, 443, 50));
    aggregator.add(event(50, 40004, 443, 60));

    let events = aggregator.take();
    assert_eq!(events.len(), 3);
    let find = |port| {
        events
            .iter()
            .find(|event| event.destination_port == Some(port))
            .unwrap()
    };
    assert_eq!(find(443).source_port, Some(40004));
    assert_eq!(find(443).count, 2);
    let dns = find(53);
    assert_eq!(dns.timestamp, UNIX_EPOCH + Duration::from_secs(10));
    assert_eq!(dns.source_port, None);
    assert_eq!((dns.upload_bytes, dns.download_bytes), (30, 60));
    assert_eq!(dns.count, 2);
    assert_eq!(find(123).count, 2);
    assert!(aggregator.take().is_empty());
}
