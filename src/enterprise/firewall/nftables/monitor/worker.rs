use std::{
    collections::{HashMap, VecDeque},
    ffi::CStr,
    io,
    os::fd::{AsRawFd, OwnedFd},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use tokio::sync::broadcast::Sender;

use super::{
    MAX_PENDING_CONNECTIONS, NFGENMSG_LEN, NFNL_SUBSYS_CTNETLINK, NFNL_SUBSYS_ULOG, NFULA_CT,
    NFULA_PAYLOAD, NFULA_PREFIX, NFULA_TIMESTAMP, NFULNL_MSG_PACKET, NLA_HDRLEN, NLA_TYPE_MASK,
    NetlinkMessage, Policy, RecvBuffer, be_u64, nl_align,
};
use crate::enterprise::firewall::{
    flow::{FlowKey, be_u16, ipv4, ipv6, parse_packet, protocol_has_ports},
    monitor::{ConnectionEvent, ConnectionStatus, TrafficDirection},
    nftables::LogTag,
};

// linux/netfilter/nfnetlink_conntrack.h
pub(super) const IPCTNL_MSG_CT_DELETE: u16 = 2;
pub(super) const CTA_TUPLE_ORIG: u16 = 1;
pub(super) const CTA_STATUS: u16 = 3;
pub(super) const CTA_COUNTERS_ORIG: u16 = 9;
pub(super) const CTA_COUNTERS_REPLY: u16 = 10;
pub(super) const CTA_TUPLE_IP: u16 = 1;
pub(super) const CTA_TUPLE_PROTO: u16 = 2;
pub(super) const CTA_IP_V4_SRC: u16 = 1;
pub(super) const CTA_IP_V4_DST: u16 = 2;
pub(super) const CTA_IP_V6_SRC: u16 = 3;
pub(super) const CTA_IP_V6_DST: u16 = 4;
pub(super) const CTA_PROTO_NUM: u16 = 1;
pub(super) const CTA_PROTO_SRC_PORT: u16 = 2;
pub(super) const CTA_PROTO_DST_PORT: u16 = 3;
pub(super) const CTA_PROTO_ICMP_ID: u16 = 4;
pub(super) const CTA_PROTO_ICMPV6_ID: u16 = 7;
pub(super) const CTA_COUNTERS_BYTES: u16 = 2;
// linux/netfilter/nf_conntrack_common.h
pub(super) const IPS_CONFIRMED: u32 = 1 << 3;

pub(super) struct DestroyedConnection {
    pub(super) key: FlowKey,
    pub(super) orig_bytes: u64,
    pub(super) reply_bytes: u64,
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

pub(super) fn parse_conntrack_destroy(payload: &[u8]) -> Option<DestroyedConnection> {
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

fn parse_conntrack_bytes(data: &[u8]) -> Option<u64> {
    attributes(data)
        .find(|(attr_type, _)| *attr_type == CTA_COUNTERS_BYTES)
        .and_then(|(_, data)| be_u64(data))
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

/// Parse `struct nfulnl_msg_packet_timestamp`.
fn parse_timestamp(data: &[u8]) -> Option<SystemTime> {
    let secs = be_u64(data)?;
    let usecs = be_u64(data.get(8..)?)?;
    UNIX_EPOCH.checked_add(Duration::from_secs(secs) + Duration::from_micros(usecs))
}

pub(super) struct Worker {
    ifname: String,
    events: Sender<ConnectionEvent>,
    /// Allowed connections awaiting destruction, by conntrack original tuple. A tuple can be
    /// reused by a new connection before the previous one is reported as destroyed.
    pub(super) pending: HashMap<FlowKey, VecDeque<ConnectionEvent>>,
    pub(super) pending_count: usize,
}

impl Worker {
    #[must_use]
    pub(super) fn new(ifname: &str, events: Sender<ConnectionEvent>) -> Self {
        Self {
            ifname: ifname.to_string(),
            events,
            pending: HashMap::new(),
            pending_count: 0,
        }
    }

    pub(super) fn run(mut self, nflog: &mnl::Socket, conntrack: &mnl::Socket, wakeup: &OwnedFd) {
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

    /// Process all logged packets waiting on `nflog`. Returns `false` if the socket failed.
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
    /// or `None` if the socket failed.
    fn receive(
        &mut self,
        socket: &mnl::Socket,
        buf: &mut RecvBuffer,
        handle: fn(&mut Self, NetlinkMessage),
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
                handle(self, message);
            }
            return Some(true);
        }
    }

    pub(super) fn handle_nflog(&mut self, message: NetlinkMessage) {
        if message.msg_type != (NFNL_SUBSYS_ULOG << 8 | NFULNL_MSG_PACKET) {
            return;
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
            return;
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
            self.emit(event);
            return;
        }
        // Without conntrack, traffic counters can't be determined.
        let Some((conntrack_key, status)) = conntrack else {
            self.emit(event);
            return;
        };
        // A packet of an already confirmed connection is a retransmission of its first packet.
        if status & IPS_CONFIRMED != 0 {
            return;
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
    }

    /// Stop tracking the oldest allowed connection; its destruction was likely missed.
    fn forget_oldest(&mut self) {
        let Some(oldest) = self
            .pending
            .iter()
            .filter_map(|(key, events)| Some((key, events.front()?.timestamp)))
            .min_by_key(|(_, timestamp)| *timestamp)
            .map(|(key, _)| key.clone())
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

    pub(super) fn handle_conntrack(&mut self, message: NetlinkMessage) {
        if message.msg_type != (NFNL_SUBSYS_CTNETLINK << 8 | IPCTNL_MSG_CT_DELETE) {
            return;
        }
        let Some(destroyed) = parse_conntrack_destroy(message.payload) else {
            debug!("Ignoring unrecognized conntrack message");
            return;
        };
        let Some(mut event) = self.take_pending(&destroyed.key) else {
            trace!("Ignoring untracked connection {:?}", destroyed.key);
            return;
        };
        // The original direction is the one in which the connection was initiated.
        (event.upload_bytes, event.download_bytes) = match event.direction {
            TrafficDirection::Outbound => (destroyed.orig_bytes, destroyed.reply_bytes),
            TrafficDirection::Inbound => (destroyed.reply_bytes, destroyed.orig_bytes),
        };
        self.emit(event);
    }

    fn emit(&self, event: ConnectionEvent) {
        // Sending fails only if there are no subscribers at the moment.
        if self.events.send(event).is_err() {
            trace!("No subscribers for connection events");
        }
    }
}
