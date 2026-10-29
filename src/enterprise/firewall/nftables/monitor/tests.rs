use super::*;

#[test]
fn test_log_tag_roundtrip() {
    for tag in [
        LogTag {
            direction: TrafficDirection::Outbound,
            verdict: Policy::Allow,
            rule_id: Some(42),
        },
        LogTag {
            direction: TrafficDirection::Outbound,
            verdict: Policy::Deny,
            rule_id: None,
        },
        LogTag {
            direction: TrafficDirection::Inbound,
            verdict: Policy::Allow,
            rule_id: None,
        },
    ] {
        assert_eq!(LogTag::from_prefix(&tag.to_prefix()), Some(tag));
    }
    assert_eq!(LogTag::from_prefix("DG:o:a:42").unwrap().rule_id, Some(42));
    assert_eq!(LogTag::from_prefix("XX:o:a:42"), None);
    assert_eq!(LogTag::from_prefix("DG:o:a:42:1"), None);
    assert_eq!(LogTag::from_prefix("DG:o:x:42"), None);
}

#[test]
fn test_nflog_group() {
    assert_eq!(nflog_group("wg0"), nflog_group("wg0"));
    assert_ne!(nflog_group("wg0"), nflog_group("wg1"));
    assert!(nflog_group("wg0") >= 0x8000);
}

fn tcp_packet() -> Vec<u8> {
    let mut packet = vec![0u8; 40];
    packet[0] = 0x45;
    packet[9] = libc::IPPROTO_TCP as u8;
    packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
    packet[16..20].copy_from_slice(&[192, 168, 1, 1]);
    packet[20..22].copy_from_slice(&51000u16.to_be_bytes());
    packet[22..24].copy_from_slice(&443u16.to_be_bytes());
    packet
}

fn tcp_key() -> FlowKey {
    FlowKey {
        protocol: libc::IPPROTO_TCP as u8,
        source: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        destination: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        source_port: 51000,
        destination_port: 443,
    }
}

#[test]
fn test_parse_ipv4_tcp_packet() {
    assert_eq!(parse_packet(&tcp_packet()), Some(tcp_key()));
}

#[test]
fn test_parse_ipv6_udp_packet_with_extension_header() {
    let mut packet = vec![0u8; 56];
    packet[0] = 0x60;
    packet[6] = libc::IPPROTO_DSTOPTS as u8;
    packet[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
    packet[24..40].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
    // Destination options header, 8 bytes long.
    packet[40] = libc::IPPROTO_UDP as u8;
    packet[48..50].copy_from_slice(&5353u16.to_be_bytes());
    packet[50..52].copy_from_slice(&53u16.to_be_bytes());

    let key = parse_packet(&packet).unwrap();
    assert_eq!(key.protocol, libc::IPPROTO_UDP as u8);
    assert_eq!(key.source_port, 5353);
    assert_eq!(key.destination_port, 53);
}

fn attr(attr_type: u16, data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&((NLA_HDRLEN + data.len()) as u16).to_ne_bytes());
    buf.extend_from_slice(&attr_type.to_ne_bytes());
    buf.extend_from_slice(data);
    buf.resize(nl_align(buf.len()), 0);
    buf
}

fn tcp_tuple() -> Vec<u8> {
    let ip = [
        attr(CTA_IP_V4_SRC, &[10, 0, 0, 2]),
        attr(CTA_IP_V4_DST, &[192, 168, 1, 1]),
    ]
    .concat();
    let proto = [
        attr(CTA_PROTO_NUM, &[libc::IPPROTO_TCP as u8]),
        attr(CTA_PROTO_SRC_PORT, &51000u16.to_be_bytes()),
        attr(CTA_PROTO_DST_PORT, &443u16.to_be_bytes()),
    ]
    .concat();
    [attr(CTA_TUPLE_IP, &ip), attr(CTA_TUPLE_PROTO, &proto)].concat()
}

fn conntrack_destroy(orig_bytes: u64, reply_bytes: u64) -> Vec<u8> {
    [
        vec![libc::AF_INET as u8, NFNETLINK_V0, 0, 0],
        attr(CTA_TUPLE_ORIG, &tcp_tuple()),
        attr(
            CTA_COUNTERS_ORIG,
            &attr(CTA_COUNTERS_BYTES, &orig_bytes.to_be_bytes()),
        ),
        attr(
            CTA_COUNTERS_REPLY,
            &attr(CTA_COUNTERS_BYTES, &reply_bytes.to_be_bytes()),
        ),
    ]
    .concat()
}

fn nflog_packet(prefix: &str, status: u32) -> Vec<u8> {
    let conntrack = [
        attr(CTA_TUPLE_ORIG, &tcp_tuple()),
        attr(CTA_STATUS, &status.to_be_bytes()),
    ]
    .concat();
    [
        vec![libc::AF_INET as u8, NFNETLINK_V0, 0, 0],
        attr(NFULA_PREFIX, format!("{prefix}\0").as_bytes()),
        attr(NFULA_PAYLOAD, &tcp_packet()),
        attr(NFULA_CT, &conntrack),
    ]
    .concat()
}

#[test]
fn test_parse_conntrack_destroy() {
    let destroyed = parse_conntrack_destroy(&conntrack_destroy(1000, 5000)).unwrap();
    assert_eq!(destroyed.key, tcp_key());
    assert_eq!(destroyed.orig_bytes, 1000);
    assert_eq!(destroyed.reply_bytes, 5000);
}

#[test]
fn test_worker_matches_connections() {
    let (events, mut receiver) = tokio::sync::broadcast::channel(10);
    let mut worker = Worker {
        ifname: "wg0".to_string(),
        events,
        pending: HashMap::new(),
        pending_count: 0,
    };
    fn nflog(payload: &[u8]) -> NetlinkMessage<'_> {
        NetlinkMessage {
            msg_type: NFNL_SUBSYS_ULOG << 8 | NFULNL_MSG_PACKET,
            seq: 0,
            payload,
        }
    }
    fn conntrack(payload: &[u8]) -> NetlinkMessage<'_> {
        NetlinkMessage {
            msg_type: NFNL_SUBSYS_CTNETLINK << 8 | IPCTNL_MSG_CT_DELETE,
            seq: 0,
            payload,
        }
    }

    // Blocked connections are reported immediately.
    worker.handle_nflog(nflog(&nflog_packet("DG:o:d:-", 0)));
    let event = receiver.try_recv().unwrap();
    assert_eq!(event.status, ConnectionStatus::Blocked);
    assert_eq!(event.rule_id, None);
    assert_eq!(event.destination_port, Some(443));

    // Two connections reusing a tuple, with a retransmission of the first packet.
    worker.handle_nflog(nflog(&nflog_packet("DG:o:a:1", 0)));
    worker.handle_nflog(nflog(&nflog_packet("DG:o:a:1", IPS_CONFIRMED)));
    worker.handle_nflog(nflog(&nflog_packet("DG:o:a:2", 0)));
    assert!(receiver.try_recv().is_err());
    assert_eq!(worker.pending_count, 2);

    worker.handle_conntrack(conntrack(&conntrack_destroy(100, 2048)));
    let event = receiver.try_recv().unwrap();
    assert_eq!(event.status, ConnectionStatus::Allowed);
    assert_eq!(event.rule_id, Some(1));
    assert_eq!((event.upload_bytes, event.download_bytes), (100, 2048));
    assert_eq!(event.download_kb(), 2);

    worker.handle_conntrack(conntrack(&conntrack_destroy(1, 2)));
    assert_eq!(receiver.try_recv().unwrap().rule_id, Some(2));
    assert!(worker.pending.is_empty());
    assert_eq!(worker.pending_count, 0);

    // Untracked connections are ignored.
    worker.handle_conntrack(conntrack(&conntrack_destroy(1, 2)));
    assert!(receiver.try_recv().is_err());

    // Events are dropped while there are no subscribers.
    drop(receiver);
    worker.handle_nflog(nflog(&nflog_packet("DG:o:d:-", 0)));
}
