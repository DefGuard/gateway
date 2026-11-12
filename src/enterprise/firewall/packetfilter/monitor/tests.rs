use std::{
    net::{IpAddr, Ipv4Addr},
    time::UNIX_EPOCH,
};

use ipnetwork::{IpNetwork, Ipv4Network};
use tokio::sync::broadcast;

use super::*;
use crate::enterprise::firewall::{Address, Policy, Port, Protocol};

const IFNAME: &str = "wg0";

/// `struct pfloghdr` followed by an IPv4 TCP packet from 10.0.0.2:51000 to 192.168.1.1:443.
fn pflog_packet(action: u8, rule_number: u32, dir: u8) -> Vec<u8> {
    let mut packet = vec![0u8; 72 + 40];
    packet[PFLOG_LENGTH] = 69;
    packet[1] = libc::AF_INET as u8;
    packet[PFLOG_ACTION] = action;
    packet[PFLOG_IFNAME_OFFSET..PFLOG_IFNAME_OFFSET + 3].copy_from_slice(IFNAME.as_bytes());
    packet[PFLOG_RULESET..PFLOG_RULESET + 3].copy_from_slice(IFNAME.as_bytes());
    packet[36..40].copy_from_slice(&1u32.to_be_bytes());
    packet[PFLOG_SUBRULENR..PFLOG_SUBRULENR + 4].copy_from_slice(&rule_number.to_be_bytes());
    packet[PFLOG_DIR] = dir;

    let ip = &mut packet[72..];
    ip[0] = 0x45;
    ip[9] = libc::IPPROTO_TCP as u8;
    ip[12..16].copy_from_slice(&[10, 0, 0, 2]);
    ip[16..20].copy_from_slice(&[192, 168, 1, 1]);
    ip[20..22].copy_from_slice(&51000u16.to_be_bytes());
    ip[22..24].copy_from_slice(&443u16.to_be_bytes());
    packet
}

/// `struct pf_state_export` for the connection in `pflog_packet()`, created in `direction`.
#[cfg(target_os = "freebsd")]
fn state(direction: u8, initiator_bytes: u64, responder_bytes: u64) -> [u8; STATE_SIZE] {
    use super::platform::{
        STATE_AF, STATE_BYTES, STATE_DIRECTION, STATE_KEY, STATE_ORIG_IFNAME, STATE_PROTO,
    };

    let mut state = [0u8; STATE_SIZE];
    state[STATE_ORIG_IFNAME..STATE_ORIG_IFNAME + 3].copy_from_slice(IFNAME.as_bytes());
    // The key is ordered by the direction in which the state was created.
    let (src, dst) = if direction == PF_OUT { (1, 0) } else { (0, 1) };
    let addr = |index: usize| STATE_KEY + index * 16;
    let port = |index: usize| STATE_KEY + 32 + index * 2;
    state[addr(src)..addr(src) + 4].copy_from_slice(&[10, 0, 0, 2]);
    state[addr(dst)..addr(dst) + 4].copy_from_slice(&[192, 168, 1, 1]);
    state[port(src)..port(src) + 2].copy_from_slice(&51000u16.to_be_bytes());
    state[port(dst)..port(dst) + 2].copy_from_slice(&443u16.to_be_bytes());
    state[STATE_BYTES..STATE_BYTES + 8].copy_from_slice(&initiator_bytes.to_ne_bytes());
    state[STATE_BYTES + 8..STATE_BYTES + 16].copy_from_slice(&responder_bytes.to_ne_bytes());
    state[STATE_AF] = libc::AF_INET as u8;
    state[STATE_PROTO] = libc::IPPROTO_TCP as u8;
    state[STATE_DIRECTION] = direction;
    state
}

/// `struct pfsync_state` for the connection in `pflog_packet()`, created in `direction`.
#[cfg(target_os = "macos")]
fn state(direction: u8, initiator_bytes: u64, responder_bytes: u64) -> [u8; STATE_SIZE] {
    use super::platform::{
        STATE_AF, STATE_BYTES, STATE_DIRECTION, STATE_EXT_LAN, STATE_LAN, STATE_PROTO,
    };

    let mut state = [0u8; STATE_SIZE];
    // For states created by incoming packets, the initiator is on the `ext_lan` side.
    let (src, dst) = if direction == PF_OUT {
        (STATE_LAN, STATE_EXT_LAN)
    } else {
        (STATE_EXT_LAN, STATE_LAN)
    };
    state[src..src + 4].copy_from_slice(&[10, 0, 0, 2]);
    state[src + 16..src + 18].copy_from_slice(&51000u16.to_be_bytes());
    state[dst..dst + 4].copy_from_slice(&[192, 168, 1, 1]);
    state[dst + 16..dst + 18].copy_from_slice(&443u16.to_be_bytes());
    for (index, bytes) in [initiator_bytes, responder_bytes].into_iter().enumerate() {
        let offset = STATE_BYTES + index * 8;
        state[offset..offset + 4].copy_from_slice(&((bytes >> 32) as u32).to_ne_bytes());
        state[offset + 4..offset + 8].copy_from_slice(&(bytes as u32).to_ne_bytes());
    }
    state[STATE_AF] = libc::AF_INET as u8;
    state[STATE_PROTO] = libc::IPPROTO_TCP as u8;
    state[STATE_DIRECTION] = direction;
    state
}

/// Worker for `IFNAME` with the given rule map, and a receiver of its events.
fn worker(rules: Vec<Option<i64>>) -> (Worker, broadcast::Receiver<ConnectionEvent>) {
    let (events, receiver) = broadcast::channel(10);
    let worker = Worker {
        ifname: IFNAME.to_string(),
        rules: Arc::new(Mutex::new(rules)),
        events,
        pf: File::open("/dev/null").unwrap(),
        pending: HashMap::new(),
        generation: 0,
        next_poll: Instant::now(),
    };
    (worker, receiver)
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
fn test_parse_pflog_header() {
    let packet = pflog_packet(PF_DROP, 3, PF_IN);
    assert_eq!(
        PflogHeader::parse(&packet),
        Some(PflogHeader {
            length: 72,
            action: PF_DROP,
            ifname: IFNAME,
            ruleset: IFNAME,
            rule_number: 3,
            dir: PF_IN,
        })
    );
    assert_eq!(PflogHeader::parse(&packet[..40]), None);
}

#[test]
fn test_parse_state() {
    // Large enough to need both halves of split counters.
    for direction in [PF_IN, PF_OUT] {
        let state = state(direction, 10, 5 << 32);
        let parsed = parse_state(&state).unwrap();
        assert_eq!(parsed.key, tcp_key());
        assert_eq!(parsed.bytes, (10, 5 << 32));
        #[cfg(target_os = "freebsd")]
        assert_eq!(parsed.ifname, Some(IFNAME));
        #[cfg(target_os = "macos")]
        assert_eq!(parsed.ifname, None);
    }
}

#[test]
fn test_parse_bpf_header() {
    let mut buf = [0u8; 32];
    #[cfg(target_os = "freebsd")]
    {
        buf[0..8].copy_from_slice(&1_700_000_000i64.to_ne_bytes());
        buf[8..16].copy_from_slice(&500i64.to_ne_bytes());
        buf[16..20].copy_from_slice(&112u32.to_ne_bytes());
        buf[24..26].copy_from_slice(&26u16.to_ne_bytes());
    }
    #[cfg(target_os = "macos")]
    {
        buf[0..4].copy_from_slice(&1_700_000_000i32.to_ne_bytes());
        buf[4..8].copy_from_slice(&500i32.to_ne_bytes());
        buf[8..12].copy_from_slice(&112u32.to_ne_bytes());
        buf[16..18].copy_from_slice(&26u16.to_ne_bytes());
    }
    let header = parse_bpf_header(&buf).unwrap();
    assert_eq!((header.length, header.captured), (26, 112));
    assert_eq!(
        header.timestamp,
        UNIX_EPOCH + Duration::from_secs(1_700_000_000) + Duration::from_micros(500)
    );
}

#[test]
fn test_rule_map() {
    let rule = |id, destination_ports: Vec<Port>| FirewallRule {
        comment: None,
        destination_addrs: vec![Address::Network(IpNetwork::V4(
            Ipv4Network::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap(),
        ))],
        destination_ports,
        id,
        verdict: Policy::Allow,
        protocols: vec![Protocol::Tcp],
        source_addrs: Vec::new(),
        ipv4: true,
    };
    let rules = [
        rule(7, vec![Port::Single(80), Port::Single(443)]),
        rule(9, Vec::new()),
    ];
    assert_eq!(
        rule_map(IFNAME, Policy::Deny, &rules),
        vec![None, None, Some(7), Some(7), Some(9)]
    );
}

#[test]
fn test_worker_tracks_connections() {
    let (mut worker, mut receiver) = worker(vec![None, Some(7), Some(8)]);
    let timestamp = SystemTime::now();

    // Blocked connections are reported immediately.
    worker.handle_pflog(&pflog_packet(PF_DROP, 2, PF_IN), timestamp);
    let event = receiver.try_recv().unwrap();
    assert_eq!(event.status, Status::Blocked);
    assert_eq!(event.rule_id, Some(8));
    assert_eq!(event.destination_port, Some(443));

    // Packets logged for other interfaces are ignored.
    let mut other = pflog_packet(PF_DROP, 2, PF_IN);
    other[PFLOG_IFNAME_OFFSET + 2] = b'1';
    worker.handle_pflog(&other, timestamp);
    assert!(receiver.try_recv().is_err());

    // Allowed connections are reported once their state is gone.
    worker.handle_pflog(&pflog_packet(PF_PASS, 1, PF_IN), timestamp);
    assert!(receiver.try_recv().is_err());
    worker.update_states(&state(PF_IN, 100, 2048));
    assert!(receiver.try_recv().is_err());
    worker.update_states(&[]);
    let event = receiver.try_recv().unwrap();
    assert_eq!(event.status, Status::Allowed);
    assert_eq!(event.direction, Direction::Outbound);
    assert_eq!(event.rule_id, Some(7));
    assert_eq!((event.upload_bytes, event.download_bytes), (100, 2048));
    assert!(worker.pending.is_empty());

    // The default policy rule has no Defguard rule ID.
    worker.handle_pflog(&pflog_packet(PF_PASS, 0, PF_IN), timestamp);
    worker.update_states(&[]);
    assert_eq!(receiver.try_recv().unwrap().rule_id, None);
}

#[test]
fn test_worker_tracks_inbound_connections() {
    let (mut worker, mut receiver) = worker(vec![None, None, Some(7)]);

    // Logged by the inbound rule, as the packet leaves through the VPN interface.
    worker.handle_pflog(&pflog_packet(PF_PASS, 1, PF_OUT), SystemTime::now());
    worker.update_states(&state(PF_OUT, 100, 2048));
    assert!(receiver.try_recv().is_err());
    worker.update_states(&[]);

    let event = receiver.try_recv().unwrap();
    assert_eq!(event.status, Status::Allowed);
    assert_eq!(event.direction, Direction::Inbound);
    assert_eq!(event.rule_id, None);
    // The VPN device is the responder.
    assert_eq!((event.upload_bytes, event.download_bytes), (2048, 100));
}

#[test]
fn test_worker_reports_vpn_to_vpn_connections_once() {
    let (mut worker, mut receiver) = worker(vec![None, None, Some(7)]);
    let timestamp = SystemTime::now();

    // Logged by an ACL rule on the way in, then by the inbound rule on the way out.
    worker.handle_pflog(&pflog_packet(PF_PASS, 2, PF_IN), timestamp);
    worker.handle_pflog(&pflog_packet(PF_PASS, 1, PF_OUT), timestamp);
    assert!(receiver.try_recv().is_err());
    worker.update_states(&[]);

    let event = receiver.try_recv().unwrap();
    assert_eq!(event.direction, Direction::Outbound);
    assert_eq!(event.rule_id, Some(7));
    assert!(receiver.try_recv().is_err());
}
