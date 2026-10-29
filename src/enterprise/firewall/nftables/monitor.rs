//! Connection monitoring for the nftables firewall.
//!
//! Rules in the Defguard table carry `log group <N> prefix "<tag>"` statements (see [`LogTag`]).
//! Established traffic is accepted before ACL rules are evaluated, so only the first packet of
//! each connection is copied to userspace through NFLOG, together with a tag identifying the
//! matching rule, its verdict and the traffic direction.
//!
//! Blocked connections are reported straight away. Allowed connections are kept until conntrack
//! reports their destruction, which carries the final byte counters. Note that conntrack destroys
//! expired entries lazily, so this may happen some time after the connection ends.

use std::{
    collections::{HashMap, VecDeque},
    ffi::CStr,
    fs, io, mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::mpsc,
    thread::{self, JoinHandle},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use tokio::sync::mpsc::{Sender, error::TrySendError};

use super::Policy;
use crate::enterprise::firewall::{
    FirewallError,
    monitor::{ConnectionEvent, ConnectionStatus, TrafficDirection},
};

// linux/netlink.h
const NLMSG_HDRLEN: usize = 16;
const NLA_HDRLEN: usize = 4;
const NLA_TYPE_MASK: u16 = 0x3fff;

// linux/netfilter/nfnetlink.h
const NFGENMSG_LEN: usize = 4;
const NFNETLINK_V0: u8 = 0;
const NFNL_SUBSYS_CTNETLINK: u16 = 1;
const NFNL_SUBSYS_ULOG: u16 = 4;
const NFNLGRP_CONNTRACK_DESTROY: u32 = 3;

// linux/netfilter/nfnetlink_log.h
const NFULNL_MSG_PACKET: u16 = 0;
const NFULNL_MSG_CONFIG: u16 = 1;
const NFULA_TIMESTAMP: u16 = 3;
const NFULA_PAYLOAD: u16 = 9;
const NFULA_PREFIX: u16 = 10;
const NFULA_CT: u16 = 18;
const NFULA_CFG_CMD: u16 = 1;
const NFULA_CFG_MODE: u16 = 2;
const NFULA_CFG_QTHRESH: u16 = 5;
const NFULA_CFG_FLAGS: u16 = 6;
const NFULNL_CFG_CMD_BIND: u8 = 1;
const NFULNL_COPY_PACKET: u8 = 2;
const NFULNL_CFG_F_CONNTRACK: u16 = 0x0004;

// linux/netfilter/nfnetlink_conntrack.h
const IPCTNL_MSG_CT_DELETE: u16 = 2;
const CTA_TUPLE_ORIG: u16 = 1;
const CTA_STATUS: u16 = 3;
const CTA_COUNTERS_ORIG: u16 = 9;
const CTA_COUNTERS_REPLY: u16 = 10;
const CTA_TUPLE_IP: u16 = 1;
const CTA_TUPLE_PROTO: u16 = 2;
const CTA_IP_V4_SRC: u16 = 1;
const CTA_IP_V4_DST: u16 = 2;
const CTA_IP_V6_SRC: u16 = 3;
const CTA_IP_V6_DST: u16 = 4;
const CTA_PROTO_NUM: u16 = 1;
const CTA_PROTO_SRC_PORT: u16 = 2;
const CTA_PROTO_DST_PORT: u16 = 3;
const CTA_PROTO_ICMP_ID: u16 = 4;
const CTA_PROTO_ICMPV6_ID: u16 = 7;
const CTA_COUNTERS_BYTES: u16 = 2;
// linux/netfilter/nf_conntrack_common.h
const IPS_CONFIRMED: u32 = 1 << 3;

// IANA protocol numbers not exposed by `libc`.
const IPPROTO_DCCP: u8 = 33;
const IPPROTO_SCTP: u8 = 132;
const IPPROTO_UDPLITE: u8 = 136;

const LOG_PREFIX: &str = "DG";
/// Number of packet bytes copied to userspace; enough for IP (with IPv6 extension headers) and
/// transport headers.
const NFLOG_COPY_RANGE: u32 = 256;
/// Send each logged packet to userspace immediately, so it's never late compared to conntrack.
const NFLOG_QUEUE_THRESHOLD: u32 = 1;
const SOCKET_BUFFER_SIZE: usize = 4 * 1024 * 1024;
/// Upper bound on the number of allowed connections awaiting conntrack destruction.
const MAX_PENDING_CONNECTIONS: usize = 65536;
const CONNTRACK_ACCT_SYSCTL: &str = "/proc/sys/net/netfilter/nf_conntrack_acct";

/// NFLOG group used for `ifname`.
///
/// Derived from the interface name, so gateways serving different interfaces on the same host do
/// not compete for one group. Kept in the upper half of the range, away from low group numbers
/// commonly used by other software.
pub(super) fn nflog_group(ifname: &str) -> u16 {
    // FNV-1a
    let hash = ifname.bytes().fold(0x811c_9dc5_u32, |hash, byte| {
        (hash ^ u32::from(byte)).wrapping_mul(0x0100_0193)
    });
    0x8000 | (hash as u16 & 0x7fff)
}

/// Information attached to logged packets through the NFLOG prefix.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct LogTag {
    pub direction: TrafficDirection,
    pub verdict: Policy,
    /// Defguard ACL rule ID; `None` for the default policy and inbound traffic.
    pub rule_id: Option<i64>,
}

impl LogTag {
    /// Format as `DG:<o|i>:<a|d>:<rule ID|->`.
    pub(super) fn to_prefix(self) -> String {
        let direction = match self.direction {
            TrafficDirection::Outbound => 'o',
            TrafficDirection::Inbound => 'i',
        };
        let verdict = match self.verdict {
            Policy::Allow => 'a',
            Policy::Deny => 'd',
        };
        match self.rule_id {
            Some(id) => format!("{LOG_PREFIX}:{direction}:{verdict}:{id}"),
            None => format!("{LOG_PREFIX}:{direction}:{verdict}:-"),
        }
    }

    fn from_prefix(prefix: &str) -> Option<Self> {
        let mut parts = prefix.split(':');
        if parts.next()? != LOG_PREFIX {
            return None;
        }
        let direction = match parts.next()? {
            "o" => TrafficDirection::Outbound,
            "i" => TrafficDirection::Inbound,
            _ => return None,
        };
        let verdict = match parts.next()? {
            "a" => Policy::Allow,
            "d" => Policy::Deny,
            _ => return None,
        };
        let rule_id = match parts.next()? {
            "-" => None,
            id => Some(id.parse().ok()?),
        };
        if parts.next().is_some() {
            return None;
        }

        Some(Self {
            direction,
            verdict,
            rule_id,
        })
    }
}

/// Monitors connections handled by the Defguard firewall on a WireGuard interface.
///
/// Monitoring stops when [`ConnectionMonitor::unregister`] is called, the monitor is dropped, or
/// the event receiver is closed.
pub struct ConnectionMonitor {
    ifname: String,
    wakeup: OwnedFd,
    thread: Option<JoinHandle<()>>,
}

impl ConnectionMonitor {
    /// Register for connection monitoring on interface `ifname`. Connection events are delivered
    /// through `events`; if the channel is full, events are dropped.
    ///
    /// Only one monitor can be registered for a given interface at a time.
    pub fn register(ifname: &str, events: Sender<ConnectionEvent>) -> Result<Self, FirewallError> {
        debug!("Registering connection monitor for interface {ifname}");
        enable_conntrack_accounting();

        let wakeup = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if wakeup < 0 {
            return Err(io::Error::last_os_error().into());
        }
        let wakeup = unsafe { OwnedFd::from_raw_fd(wakeup) };

        let group = nflog_group(ifname);
        let worker = Worker {
            ifname: ifname.to_string(),
            events,
            pending: HashMap::new(),
            pending_count: 0,
        };
        let worker_wakeup = wakeup.try_clone()?;
        // `mnl::Socket` can't be sent between threads, so sockets are opened by the worker thread.
        let (setup_tx, setup_rx) = mpsc::sync_channel(1);
        let thread = thread::Builder::new()
            .name(format!("monitor-{ifname}"))
            .spawn(move || match open_sockets(group) {
                Ok((nflog, conntrack)) => {
                    let _ = setup_tx.send(Ok(()));
                    worker.run(&nflog, &conntrack, &worker_wakeup);
                }
                Err(err) => {
                    let _ = setup_tx.send(Err(err));
                }
            })?;
        let setup = setup_rx.recv().unwrap_or_else(|_| {
            Err(FirewallError::NetlinkError(
                "Connection monitor thread exited unexpectedly".to_string(),
            ))
        });
        if let Err(err) = setup {
            let _ = thread.join();
            return Err(err);
        }

        info!("Registered connection monitor for interface {ifname} (NFLOG group {group})");

        Ok(Self {
            ifname: ifname.to_string(),
            wakeup,
            thread: Some(thread),
        })
    }

    /// Unregister from connection monitoring. Connections still in progress are not reported.
    pub fn unregister(mut self) {
        self.stop();
    }

    fn stop(&mut self) {
        let Some(thread) = self.thread.take() else {
            return;
        };
        let value = 1u64.to_ne_bytes();
        let ret =
            unsafe { libc::write(self.wakeup.as_raw_fd(), value.as_ptr().cast(), value.len()) };
        if ret < 0 {
            error!(
                "Failed to stop connection monitor for interface {}: {}",
                self.ifname,
                io::Error::last_os_error()
            );
            return;
        }
        if thread.join().is_err() {
            error!(
                "Connection monitor thread for interface {} panicked",
                self.ifname
            );
        }
        info!(
            "Unregistered connection monitor for interface {}",
            self.ifname
        );
    }
}

impl Drop for ConnectionMonitor {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Open and configure the NFLOG and conntrack sockets.
fn open_sockets(group: u16) -> Result<(mnl::Socket, mnl::Socket), FirewallError> {
    // Subscribing to conntrack events loads ctnetlink, which NFLOG needs to attach conntrack
    // information to logged packets.
    let conntrack = open_socket(1 << (NFNLGRP_CONNTRACK_DESTROY - 1))?;

    let nflog = open_socket(0)?;
    nflog_request(&nflog, 1, group, &[(NFULA_CFG_CMD, &[NFULNL_CFG_CMD_BIND])]).map_err(|err| {
        FirewallError::NetlinkError(format!("Failed to bind to NFLOG group {group}: {err}"))
    })?;
    // struct nfulnl_msg_config_mode
    let mut mode = NFLOG_COPY_RANGE.to_be_bytes().to_vec();
    mode.extend_from_slice(&[NFULNL_COPY_PACKET, 0]);
    nflog_request(
        &nflog,
        2,
        group,
        &[
            (NFULA_CFG_MODE, &mode),
            (NFULA_CFG_QTHRESH, &NFLOG_QUEUE_THRESHOLD.to_be_bytes()),
            (NFULA_CFG_FLAGS, &NFULNL_CFG_F_CONNTRACK.to_be_bytes()),
        ],
    )
    .map_err(|err| {
        FirewallError::NetlinkError(format!("Failed to configure NFLOG group {group}: {err}"))
    })?;

    // From now on, sockets are only read after polling.
    set_nonblocking(&nflog)?;
    set_nonblocking(&conntrack)?;

    Ok((nflog, conntrack))
}

/// Traffic counters are only gathered by conntrack when accounting is enabled.
fn enable_conntrack_accounting() {
    if fs::read_to_string(CONNTRACK_ACCT_SYSCTL).is_ok_and(|value| value.trim() == "1") {
        return;
    }
    match fs::write(CONNTRACK_ACCT_SYSCTL, "1") {
        Ok(()) => debug!("Enabled conntrack accounting"),
        Err(err) => warn!(
            "Failed to enable conntrack accounting in {CONNTRACK_ACCT_SYSCTL}: {err}. Traffic \
            counters will not be available."
        ),
    }
}

/// Uniquely identifies a connection, as seen in its original direction.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct FlowKey {
    protocol: u8,
    source: IpAddr,
    destination: IpAddr,
    /// Source port, or ICMP identifier.
    source_port: u16,
    destination_port: u16,
}

struct Worker {
    ifname: String,
    events: Sender<ConnectionEvent>,
    /// Allowed connections awaiting destruction, by conntrack original tuple. A tuple can be
    /// reused by a new connection before the previous one is reported as destroyed.
    pending: HashMap<FlowKey, VecDeque<ConnectionEvent>>,
    pending_count: usize,
}

impl Worker {
    fn run(mut self, nflog: &mnl::Socket, conntrack: &mnl::Socket, wakeup: &OwnedFd) {
        let mut nflog_buf = RecvBuffer::new();
        let mut conntrack_buf = RecvBuffer::new();
        'poll: loop {
            let mut fds =
                [nflog.as_raw_fd(), conntrack.as_raw_fd(), wakeup.as_raw_fd()].map(|fd| {
                    libc::pollfd {
                        fd,
                        events: libc::POLLIN,
                        revents: 0,
                    }
                });
            if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) } < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                error!(
                    "Connection monitor for interface {} failed: {err}",
                    self.ifname
                );
                break;
            }
            if fds[2].revents != 0 {
                break;
            }
            // The first packet of a connection is logged before conntrack can destroy it, so pick
            // up all logged packets before each batch of conntrack events.
            loop {
                if !self.drain(nflog, &mut nflog_buf) {
                    break 'poll;
                }
                if fds[1].revents == 0 {
                    break;
                }
                match self.receive(conntrack, &mut conntrack_buf, Self::handle_conntrack) {
                    Some(true) => {}
                    Some(false) => break,
                    None => break 'poll,
                }
            }
        }
        // Closing the NFLOG socket releases the group.
        debug!("Connection monitor for interface {} stopped", self.ifname);
    }

    /// Process all logged packets waiting on `nflog`. Returns `false` if monitoring should stop.
    fn drain(&mut self, nflog: &mnl::Socket, buf: &mut RecvBuffer) -> bool {
        loop {
            match self.receive(nflog, buf, Self::handle_nflog) {
                Some(true) => {}
                Some(false) => return true,
                None => return false,
            }
        }
    }

    /// Process one batch of messages waiting on `socket`. Returns whether there were any messages,
    /// or `None` if monitoring should stop.
    fn receive(
        &mut self,
        socket: &mnl::Socket,
        buf: &mut RecvBuffer,
        handle: fn(&mut Self, NetlinkMessage) -> bool,
    ) -> Option<bool> {
        loop {
            let messages = match socket.recv(&mut buf.0) {
                Ok(messages) => messages,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Some(false),
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) if err.raw_os_error() == Some(libc::ENOBUFS) => {
                    warn!(
                        "Connection monitor for interface {} can't keep up, some events were lost",
                        self.ifname
                    );
                    return Some(true);
                }
                Err(err) => {
                    error!(
                        "Connection monitor for interface {} failed: {err}",
                        self.ifname
                    );
                    return None;
                }
            };
            for message in messages {
                let message = match message.map(NetlinkMessage::parse) {
                    Ok(Some(message)) => message,
                    Ok(None) => continue,
                    Err(err) => {
                        warn!("Received invalid netlink message: {err}");
                        break;
                    }
                };
                if !handle(self, message) {
                    return None;
                }
            }
            return Some(true);
        }
    }

    fn handle_nflog(&mut self, message: NetlinkMessage) -> bool {
        if message.msg_type != (NFNL_SUBSYS_ULOG << 8 | NFULNL_MSG_PACKET) {
            return true;
        }
        let mut tag = None;
        let mut key = None;
        let mut timestamp = None;
        let mut conntrack = None;
        for (attr_type, data) in attributes(message.payload.get(NFGENMSG_LEN..).unwrap_or_default())
        {
            match attr_type {
                NFULA_PREFIX => {
                    tag = CStr::from_bytes_until_nul(data)
                        .ok()
                        .and_then(|prefix| prefix.to_str().ok())
                        .and_then(LogTag::from_prefix);
                }
                NFULA_PAYLOAD => key = parse_packet(data),
                NFULA_TIMESTAMP => timestamp = parse_timestamp(data),
                NFULA_CT => conntrack = parse_conntrack_info(data),
                _ => {}
            }
        }
        let (Some(tag), Some(key)) = (tag, key) else {
            debug!("Ignoring unrecognized NFLOG packet");
            return true;
        };

        let has_ports = protocol_has_ports(key.protocol);
        let event = ConnectionEvent {
            timestamp: timestamp.unwrap_or_else(SystemTime::now),
            direction: tag.direction,
            status: match tag.verdict {
                Policy::Allow => ConnectionStatus::Allowed,
                Policy::Deny => ConnectionStatus::Blocked,
            },
            protocol: key.protocol,
            source: key.source,
            source_port: has_ports.then_some(key.source_port),
            destination: key.destination,
            destination_port: has_ports.then_some(key.destination_port),
            rule_id: tag.rule_id,
            upload_bytes: 0,
            download_bytes: 0,
        };

        if event.status == ConnectionStatus::Blocked {
            return self.emit(event);
        }
        // Without conntrack, traffic counters can't be determined.
        let Some((conntrack_key, status)) = conntrack else {
            return self.emit(event);
        };
        // A packet of an already confirmed connection is a retransmission of its first packet.
        if status & IPS_CONFIRMED != 0 {
            return true;
        }
        if self.pending_count >= MAX_PENDING_CONNECTIONS {
            self.forget_oldest();
        }
        trace!("Tracking allowed connection {conntrack_key:?}");
        self.pending
            .entry(conntrack_key)
            .or_default()
            .push_back(event);
        self.pending_count += 1;
        true
    }

    /// Stop tracking the oldest allowed connection; its destruction was likely missed.
    fn forget_oldest(&mut self) {
        let Some(oldest) = self
            .pending
            .iter()
            .filter_map(|(key, events)| Some((key, events.front()?.timestamp)))
            .min_by_key(|(_, timestamp)| *timestamp)
            .map(|(key, _)| *key)
        else {
            return;
        };
        debug!("Too many tracked connections, forgetting {oldest:?}");
        self.take_pending(&oldest);
    }

    fn take_pending(&mut self, key: &FlowKey) -> Option<ConnectionEvent> {
        let events = self.pending.get_mut(key)?;
        let event = events.pop_front();
        if events.is_empty() {
            self.pending.remove(key);
        }
        if event.is_some() {
            self.pending_count -= 1;
        }
        event
    }

    fn handle_conntrack(&mut self, message: NetlinkMessage) -> bool {
        if message.msg_type != (NFNL_SUBSYS_CTNETLINK << 8 | IPCTNL_MSG_CT_DELETE) {
            return true;
        }
        let Some(destroyed) = parse_conntrack_destroy(message.payload) else {
            debug!("Ignoring unrecognized conntrack message");
            return true;
        };
        let Some(mut event) = self.take_pending(&destroyed.key) else {
            trace!("Ignoring untracked connection {:?}", destroyed.key);
            return true;
        };
        // The original direction is the one in which the connection was initiated.
        (event.upload_bytes, event.download_bytes) = match event.direction {
            TrafficDirection::Outbound => (destroyed.orig_bytes, destroyed.reply_bytes),
            TrafficDirection::Inbound => (destroyed.reply_bytes, destroyed.orig_bytes),
        };
        self.emit(event)
    }

    /// Returns `false` if the receiver is gone.
    fn emit(&self, event: ConnectionEvent) -> bool {
        match self.events.try_send(event) {
            Ok(()) => true,
            Err(TrySendError::Full(event)) => {
                warn!("Connection event queue is full, dropping {event:?}");
                true
            }
            Err(TrySendError::Closed(_)) => {
                debug!(
                    "Connection event receiver for interface {} closed",
                    self.ifname
                );
                false
            }
        }
    }
}

fn protocol_has_ports(protocol: u8) -> bool {
    matches!(i32::from(protocol), libc::IPPROTO_TCP | libc::IPPROTO_UDP)
        || matches!(protocol, IPPROTO_DCCP | IPPROTO_SCTP | IPPROTO_UDPLITE)
}

fn be_u16(data: &[u8]) -> Option<u16> {
    Some(u16::from_be_bytes(data.get(..2)?.try_into().ok()?))
}

fn be_u64(data: &[u8]) -> Option<u64> {
    Some(u64::from_be_bytes(data.get(..8)?.try_into().ok()?))
}

fn ipv4(data: &[u8]) -> Option<IpAddr> {
    Some(IpAddr::V4(Ipv4Addr::from(
        <[u8; 4]>::try_from(data.get(..4)?).ok()?,
    )))
}

fn ipv6(data: &[u8]) -> Option<IpAddr> {
    Some(IpAddr::V6(Ipv6Addr::from(
        <[u8; 16]>::try_from(data.get(..16)?).ok()?,
    )))
}

/// Parse `struct nfulnl_msg_packet_timestamp`.
fn parse_timestamp(data: &[u8]) -> Option<SystemTime> {
    let secs = be_u64(data)?;
    let usecs = be_u64(data.get(8..)?)?;
    UNIX_EPOCH.checked_add(Duration::from_secs(secs) + Duration::from_micros(usecs))
}

/// Extract connection details from a packet, starting at the network header.
fn parse_packet(packet: &[u8]) -> Option<FlowKey> {
    let (protocol, source, destination, transport) = match packet.first()? >> 4 {
        4 => {
            let header_len = usize::from(packet[0] & 0x0f) * 4;
            (
                *packet.get(9)?,
                ipv4(packet.get(12..)?)?,
                ipv4(packet.get(16..)?)?,
                packet.get(header_len..)?,
            )
        }
        6 => {
            let mut next_header = *packet.get(6)?;
            let mut offset = 40;
            loop {
                match i32::from(next_header) {
                    libc::IPPROTO_HOPOPTS | libc::IPPROTO_ROUTING | libc::IPPROTO_DSTOPTS => {
                        let header = packet.get(offset..offset + 2)?;
                        next_header = header[0];
                        offset += (usize::from(header[1]) + 1) * 8;
                    }
                    libc::IPPROTO_FRAGMENT => {
                        next_header = *packet.get(offset)?;
                        offset += 8;
                    }
                    _ => break,
                }
            }
            (
                next_header,
                ipv6(packet.get(8..)?)?,
                ipv6(packet.get(24..)?)?,
                packet.get(offset..)?,
            )
        }
        _ => return None,
    };

    // Match the way conntrack identifies connections.
    let (source_port, destination_port) = match i32::from(protocol) {
        libc::IPPROTO_ICMP | libc::IPPROTO_ICMPV6 => (be_u16(transport.get(4..)?)?, 0),
        _ if protocol_has_ports(protocol) => (be_u16(transport)?, be_u16(transport.get(2..)?)?),
        _ => (0, 0),
    };

    Some(FlowKey {
        protocol,
        source,
        destination,
        source_port,
        destination_port,
    })
}

struct DestroyedConnection {
    key: FlowKey,
    orig_bytes: u64,
    reply_bytes: u64,
}

fn parse_conntrack_destroy(payload: &[u8]) -> Option<DestroyedConnection> {
    let mut key = None;
    let mut orig_bytes = 0;
    let mut reply_bytes = 0;
    for (attr_type, data) in attributes(payload.get(NFGENMSG_LEN..)?) {
        match attr_type {
            CTA_TUPLE_ORIG => key = parse_conntrack_tuple(data),
            CTA_COUNTERS_ORIG => orig_bytes = parse_conntrack_bytes(data).unwrap_or_default(),
            CTA_COUNTERS_REPLY => reply_bytes = parse_conntrack_bytes(data).unwrap_or_default(),
            _ => {}
        }
    }

    Some(DestroyedConnection {
        key: key?,
        orig_bytes,
        reply_bytes,
    })
}

fn parse_conntrack_tuple(data: &[u8]) -> Option<FlowKey> {
    let mut protocol = None;
    let mut source = None;
    let mut destination = None;
    let mut source_port = 0;
    let mut destination_port = 0;
    for (attr_type, data) in attributes(data) {
        match attr_type {
            CTA_TUPLE_IP => {
                for (attr_type, data) in attributes(data) {
                    match attr_type {
                        CTA_IP_V4_SRC => source = ipv4(data),
                        CTA_IP_V4_DST => destination = ipv4(data),
                        CTA_IP_V6_SRC => source = ipv6(data),
                        CTA_IP_V6_DST => destination = ipv6(data),
                        _ => {}
                    }
                }
            }
            CTA_TUPLE_PROTO => {
                for (attr_type, data) in attributes(data) {
                    match attr_type {
                        CTA_PROTO_NUM => protocol = data.first().copied(),
                        CTA_PROTO_SRC_PORT | CTA_PROTO_ICMP_ID | CTA_PROTO_ICMPV6_ID => {
                            source_port = be_u16(data)?;
                        }
                        CTA_PROTO_DST_PORT => destination_port = be_u16(data)?,
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    Some(FlowKey {
        protocol: protocol?,
        source: source?,
        destination: destination?,
        source_port,
        destination_port,
    })
}

/// Parse conntrack information attached to a logged packet: original tuple and status.
fn parse_conntrack_info(data: &[u8]) -> Option<(FlowKey, u32)> {
    let mut key = None;
    let mut status = None;
    for (attr_type, data) in attributes(data) {
        match attr_type {
            CTA_TUPLE_ORIG => key = parse_conntrack_tuple(data),
            CTA_STATUS => {
                status = Some(u32::from_be_bytes(data.get(..4)?.try_into().ok()?));
            }
            _ => {}
        }
    }

    Some((key?, status?))
}

fn parse_conntrack_bytes(data: &[u8]) -> Option<u64> {
    attributes(data)
        .find(|(attr_type, _)| *attr_type == CTA_COUNTERS_BYTES)
        .and_then(|(_, data)| be_u64(data))
}

const fn nl_align(len: usize) -> usize {
    (len + 3) & !3
}

/// Receive buffer aligned to `nlmsghdr`, as required by `mnl`.
#[repr(C, align(4))]
struct RecvBuffer([u8; 65536]);

impl RecvBuffer {
    fn new() -> Box<Self> {
        Box::new(Self([0; 65536]))
    }
}

struct NetlinkMessage<'a> {
    msg_type: u16,
    seq: u32,
    payload: &'a [u8],
}

impl<'a> NetlinkMessage<'a> {
    /// Parse a single message, as returned by `mnl::NlMessages`.
    fn parse(message: &'a [u8]) -> Option<Self> {
        Some(Self {
            msg_type: u16::from_ne_bytes(message.get(4..6)?.try_into().ok()?),
            seq: u32::from_ne_bytes(message.get(8..12)?.try_into().ok()?),
            payload: message.get(NLMSG_HDRLEN..)?,
        })
    }
}

fn attributes(mut buf: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    std::iter::from_fn(move || {
        let header = buf.get(..NLA_HDRLEN)?;
        let len = usize::from(u16::from_ne_bytes([header[0], header[1]]));
        let attr_type = u16::from_ne_bytes([header[2], header[3]]) & NLA_TYPE_MASK;
        if !(NLA_HDRLEN..=buf.len()).contains(&len) {
            return None;
        }
        let data = &buf[NLA_HDRLEN..len];
        buf = buf.get(nl_align(len)..).unwrap_or_default();
        Some((attr_type, data))
    })
}

/// Open a `NETLINK_NETFILTER` socket subscribed to multicast `groups` (bitmask).
fn open_socket(groups: u32) -> io::Result<mnl::Socket> {
    let socket = mnl::Socket::open(mnl::Bus::Netfilter)?;
    // Don't leak the socket into child processes.
    if unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    socket.bind(groups, mnl::mnl_sys::MNL_SOCKET_AUTOPID)?;

    // Enlarge the receive buffer to avoid losing events during bursts.
    // SO_RCVBUFFORCE exceeds the `rmem_max` limit, but requires CAP_NET_ADMIN.
    let size = libc::c_int::try_from(SOCKET_BUFFER_SIZE).unwrap_or(libc::c_int::MAX);
    let set = |option| unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            option,
            (&raw const size).cast(),
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        ) == 0
    };
    if !set(libc::SO_RCVBUFFORCE) && !set(libc::SO_RCVBUF) {
        warn!(
            "Failed to set netlink socket receive buffer size: {}",
            io::Error::last_os_error()
        );
    }

    Ok(socket)
}

fn set_nonblocking(socket: &mnl::Socket) -> io::Result<()> {
    let fd = socket.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Send NFLOG configuration message and wait for acknowledgement.
fn nflog_request(
    socket: &mnl::Socket,
    seq: u32,
    res_id: u16,
    attrs: &[(u16, &[u8])],
) -> io::Result<()> {
    let mut message = vec![0; NLMSG_HDRLEN];
    // struct nfgenmsg
    message.extend_from_slice(&[libc::AF_UNSPEC as u8, NFNETLINK_V0]);
    message.extend_from_slice(&res_id.to_be_bytes());
    for (attr_type, data) in attrs {
        let len = (NLA_HDRLEN + data.len()) as u16;
        message.extend_from_slice(&len.to_ne_bytes());
        message.extend_from_slice(&attr_type.to_ne_bytes());
        message.extend_from_slice(data);
        message.resize(nl_align(message.len()), 0);
    }
    // struct nlmsghdr
    let len = message.len() as u32;
    let flags = (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16;
    message[0..4].copy_from_slice(&len.to_ne_bytes());
    message[4..6].copy_from_slice(&(NFNL_SUBSYS_ULOG << 8 | NFULNL_MSG_CONFIG).to_ne_bytes());
    message[6..8].copy_from_slice(&flags.to_ne_bytes());
    message[8..12].copy_from_slice(&seq.to_ne_bytes());
    socket.send(&message)?;

    // Skip other messages (e.g. logged packets) until the acknowledgement arrives.
    let mut buf = RecvBuffer::new();
    loop {
        for message in socket.recv(&mut buf.0)? {
            let message = message?;
            if NetlinkMessage::parse(message).is_some_and(|parsed| {
                parsed.seq == seq && parsed.msg_type == libc::NLMSG_ERROR as u16
            }) {
                return mnl::cb_run(message, seq, socket.portid()).map(|_| ());
            }
        }
    }
}

#[cfg(test)]
mod tests;
