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

mod worker;

use std::{
    fs, io, mem,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::mpsc,
    thread::{self, JoinHandle},
};

use tokio::sync::broadcast::Sender;

use self::worker::Worker;
use super::Policy;
use crate::enterprise::firewall::{
    FirewallError, FirewallRule,
    monitor::{ConnectionEvent, TrafficDirection},
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
        let id = match self.rule_id {
            Some(id) => id.to_string(),
            None => String::from("-"),
        };
        format!(
            "{LOG_PREFIX}:{}:{}:{id}",
            self.direction.as_str(),
            self.verdict.as_str()
        )
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
/// Monitoring stops when [`ConnectionMonitor::unregister`] is called or the monitor is dropped.
pub struct ConnectionMonitor {
    ifname: String,
    wakeup: OwnedFd,
    thread: Option<JoinHandle<()>>,
}

impl ConnectionMonitor {
    /// Register for connection monitoring on interface `ifname`. Connection events are published
    /// to `events`; events are dropped while there are no subscribers.
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
        let worker = Worker::new(ifname, events);
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

    /// Inform the monitor about the current firewall rules. Rule IDs are carried in NFLOG
    /// prefixes, so there's nothing to do.
    pub(crate) fn update_rules(&self, _rules: &[FirewallRule]) {}

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

fn be_u64(data: &[u8]) -> Option<u64> {
    Some(u64::from_be_bytes(data.get(..8)?.try_into().ok()?))
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
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
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
