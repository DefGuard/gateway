//! Connection monitoring for the Packet Filter firewall on FreeBSD and macOS.
//!
//! Defguard rules are created with the `log` option, so pf passes the packet which creates a state
//! (or is blocked) to the `pflog0` interface, which is read through BPF. Each logged packet carries
//! the number of the matching rule within the Defguard anchor, which is mapped back to the Defguard
//! rule (see [`ConnectionMonitor::update_rules`]).
//!
//! Blocked connections are reported straight away. pf has no notification of state removal, so
//! while allowed connections are in progress, the state table is polled periodically. Once a state
//! is gone, its connection is reported with the traffic counters from the last poll; traffic since
//! then is not counted.

#[cfg(target_os = "freebsd")]
mod freebsd;
#[cfg(target_os = "macos")]
mod macos;

use std::{
    collections::HashMap,
    ffi::CStr,
    fs::File,
    io, mem,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime},
};

use defguard_wireguard_rs::bsd::ioctl::iow;
use libc::{c_int, c_uint, c_ulong};
use tokio::sync::broadcast::Sender;

#[cfg(target_os = "freebsd")]
use self::freebsd as platform;
#[cfg(target_os = "macos")]
use self::macos as platform;
use self::platform::{STATE_SIZE, open_bpf, parse_bpf_header, parse_state, read_states};
use super::rule::PacketFilterRule;
use crate::enterprise::firewall::{
    FirewallError, FirewallRule,
    flow::{FlowKey, parse_packet, protocol_has_ports},
    monitor::{ConnectionEvent, ConnectionStatus, TrafficDirection},
};

const DEV_PF: &str = "/dev/pf";
const PFLOG_IFNAME: &str = "pflog0";

// net/bpf.h
// `_IOR('B', 102, u_int)`; not using `ior()`, which encodes the direction as `IOC_IN`.
const BIOCGBLEN: c_ulong = 0x4000_0000 | (4 << 16) | ((b'B' as c_ulong) << 8) | 102;
const BIOCSETIF: c_ulong = iow::<libc::ifreq>(b'B', 108);
const BIOCIMMEDIATE: c_ulong = iow::<c_uint>(b'B', 112);

// net/if_pflog.h: offsets in `struct pfloghdr`.
const PFLOG_LENGTH: usize = 0;
const PFLOG_ACTION: usize = 2;
const PFLOG_IFNAME_OFFSET: usize = 4;
const PFLOG_RULESET: usize = 20;
const PFLOG_SUBRULENR: usize = 40;
const PFLOG_DIR: usize = 60;
const PFLOG_ALIGNMENT: usize = 4;

// pf.h
const PF_PASS: u8 = 0;
const PF_DROP: u8 = 1;
const PF_IN: u8 = 1;
const PF_OUT: u8 = 2;

/// How often the state table is read while allowed connections are in progress.
const STATE_POLL_INTERVAL: Duration = Duration::from_secs(5);
/// Upper bound on the number of allowed connections in progress.
const MAX_PENDING_CONNECTIONS: usize = 65536;

/// Defguard rule IDs, indexed by rule number within the Defguard anchor.
type RuleMap = Arc<Mutex<Vec<Option<i64>>>>;

/// Monitors connections handled by the Defguard firewall on a WireGuard interface.
///
/// Monitoring stops when [`ConnectionMonitor::unregister`] is called or the monitor is dropped.
pub struct ConnectionMonitor {
    ifname: String,
    rules: RuleMap,
    wakeup: OwnedFd,
    thread: Option<JoinHandle<()>>,
}

impl ConnectionMonitor {
    /// Register for connection monitoring on interface `ifname`. Connection events are published
    /// to `events`; events are dropped while there are no subscribers.
    ///
    /// Requires the `pflog0` interface.
    pub fn register(ifname: &str, events: Sender<ConnectionEvent>) -> Result<Self, FirewallError> {
        debug!("Registering connection monitor for interface {ifname}");
        let bpf = open_pflog()?;
        let pf = File::open(DEV_PF)?;
        let (wakeup_rx, wakeup) = pipe()?;

        let rules = RuleMap::default();
        let worker = Worker {
            ifname: ifname.to_string(),
            rules: Arc::clone(&rules),
            events,
            pf,
            pending: HashMap::new(),
            generation: 0,
            next_poll: Instant::now(),
        };
        let thread = thread::Builder::new()
            .name(format!("monitor-{ifname}"))
            .spawn(move || worker.run(&bpf, &wakeup_rx))?;

        info!("Registered connection monitor for interface {ifname}");

        Ok(Self {
            ifname: ifname.to_string(),
            rules,
            wakeup,
            thread: Some(thread),
        })
    }

    /// Unregister from connection monitoring. Connections still in progress are not reported.
    pub fn unregister(mut self) {
        self.stop();
    }

    /// Inform the monitor about the current firewall rules, so logged packets can be attributed to
    /// Defguard rules. Must be called whenever the rules are applied.
    pub(crate) fn update_rules(&self, rules: &[FirewallRule]) {
        *self.rules.lock().expect("Failed to lock rule map") = rule_map(&self.ifname, rules);
    }

    fn stop(&mut self) {
        let Some(thread) = self.thread.take() else {
            return;
        };
        let ret = unsafe { libc::write(self.wakeup.as_raw_fd(), [0u8].as_ptr().cast(), 1) };
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

/// Map rule numbers within the Defguard anchor to Defguard rule IDs. Follows the order in which
/// `FirewallApi::add_rules` adds rules: the default policy first, then each Defguard rule expanded
/// into Packet Filter rules.
fn rule_map(ifname: &str, rules: &[FirewallRule]) -> Vec<Option<i64>> {
    let mut map = vec![None];
    for rule in rules {
        let count = PacketFilterRule::from_firewall_rule(ifname, rule).len();
        map.extend(std::iter::repeat_n(Some(rule.id), count));
    }
    map
}

/// Open a BPF device listening on `pflog0`.
fn open_pflog() -> Result<File, FirewallError> {
    let bpf = open_bpf()?;

    let mut ifreq: libc::ifreq = unsafe { mem::zeroed() };
    for (dst, src) in ifreq.ifr_name.iter_mut().zip(PFLOG_IFNAME.bytes()) {
        *dst = src as libc::c_char;
    }
    if unsafe { libc::ioctl(bpf.as_raw_fd(), BIOCSETIF, &raw const ifreq) } < 0 {
        return Err(FirewallError::InvalidConfiguration(format!(
            "Failed to listen on {PFLOG_IFNAME}: {}. {}",
            io::Error::last_os_error(),
            platform::PFLOG_HINT
        )));
    }
    // Deliver packets as soon as they arrive, instead of when the buffer fills up.
    let immediate: c_uint = 1;
    if unsafe { libc::ioctl(bpf.as_raw_fd(), BIOCIMMEDIATE, &raw const immediate) } < 0 {
        return Err(io::Error::last_os_error().into());
    }

    Ok(bpf)
}

/// Create a pipe used to wake up the monitor thread; returns (read end, write end).
fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let fds = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    for fd in [&fds.0, &fds.1] {
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(fds)
}

/// Allowed connection in progress.
struct Pending {
    event: ConnectionEvent,
    /// Bytes sent by the initiator and the responder, as of the last state poll.
    bytes: (u64, u64),
    /// Last state poll which found this connection.
    generation: u64,
}

struct Worker {
    ifname: String,
    rules: RuleMap,
    events: Sender<ConnectionEvent>,
    pf: File,
    pending: HashMap<FlowKey, Pending>,
    /// Number of state polls so far.
    generation: u64,
    next_poll: Instant,
}

impl Worker {
    fn run(mut self, bpf: &File, wakeup: &OwnedFd) {
        let mut buf_len: c_uint = 0;
        if unsafe { libc::ioctl(bpf.as_raw_fd(), BIOCGBLEN, &raw mut buf_len) } < 0 {
            error!(
                "Connection monitor for interface {} failed to get BPF buffer size: {}",
                self.ifname,
                io::Error::last_os_error()
            );
            return;
        }
        // Use `u64` to keep the buffer aligned for `struct bpf_hdr`.
        let mut buf = vec![0u64; (buf_len as usize).div_ceil(8)];

        loop {
            // Wake up for the next state poll only while there are connections in progress.
            let timeout = if self.pending.is_empty() {
                -1
            } else {
                let remaining = self.next_poll.saturating_duration_since(Instant::now());
                c_int::try_from(remaining.as_millis()).unwrap_or(c_int::MAX)
            };
            let mut fds = [bpf.as_raw_fd(), wakeup.as_raw_fd()].map(|fd| libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            });
            if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) } < 0 {
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
            if fds[1].revents != 0 {
                break;
            }
            if fds[0].revents != 0 {
                let len = unsafe {
                    libc::read(
                        bpf.as_raw_fd(),
                        buf.as_mut_ptr().cast(),
                        buf.len() * mem::size_of::<u64>(),
                    )
                };
                if len < 0 {
                    let err = io::Error::last_os_error();
                    if err.kind() != io::ErrorKind::Interrupted {
                        error!(
                            "Connection monitor for interface {} failed to read from BPF: {err}",
                            self.ifname
                        );
                        break;
                    }
                } else {
                    let bytes = unsafe {
                        std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), len as usize)
                    };
                    self.handle_bpf(bytes);
                }
            }
            if !self.pending.is_empty() && Instant::now() >= self.next_poll {
                self.poll_states();
            }
        }
        debug!("Connection monitor for interface {} stopped", self.ifname);
    }

    /// Process packets read from BPF; each is preceded by `struct bpf_hdr`.
    fn handle_bpf(&mut self, mut buf: &[u8]) {
        while let Some(header) = parse_bpf_header(buf) {
            let end = header.length + header.captured;
            let Some(packet) = buf.get(header.length..end) else {
                break;
            };
            self.handle_pflog(packet, header.timestamp);
            buf = buf
                .get(end.next_multiple_of(platform::BPF_ALIGNMENT)..)
                .unwrap_or_default();
        }
    }

    /// Process a packet logged by pf, preceded by `struct pfloghdr`.
    fn handle_pflog(&mut self, packet: &[u8], timestamp: SystemTime) {
        let Some(log) = PflogHeader::parse(packet) else {
            debug!("Ignoring unrecognized pflog packet");
            return;
        };
        // The ruleset is the name of the anchor, which is the interface name.
        if log.ifname != self.ifname || log.ruleset != self.ifname {
            return;
        }
        let status = match log.action {
            PF_PASS => ConnectionStatus::Allowed,
            PF_DROP => ConnectionStatus::Blocked,
            _ => return,
        };
        let direction = match log.dir {
            PF_IN => TrafficDirection::Outbound,
            PF_OUT => TrafficDirection::Inbound,
            _ => return,
        };
        let Some(key) = packet.get(log.length..).and_then(parse_packet) else {
            debug!("Ignoring unrecognized packet logged by pf");
            return;
        };
        let rule_id = self
            .rules
            .lock()
            .expect("Failed to lock rule map")
            .get(log.rule_number as usize)
            .copied()
            .flatten();

        let has_ports = protocol_has_ports(key.protocol);
        let event = ConnectionEvent {
            timestamp,
            direction,
            status,
            protocol: key.protocol,
            source: key.source,
            source_port: has_ports.then_some(key.source_port),
            destination: key.destination,
            destination_port: has_ports.then_some(key.destination_port),
            rule_id,
            upload_bytes: 0,
            download_bytes: 0,
        };

        if status == ConnectionStatus::Blocked {
            self.emit(event);
            return;
        }
        if self.pending.is_empty() {
            self.next_poll = Instant::now() + STATE_POLL_INTERVAL;
        }
        if self.pending.len() >= MAX_PENDING_CONNECTIONS && !self.pending.contains_key(&key) {
            self.forget_oldest();
        }
        trace!("Tracking allowed connection {key:?}");
        let pending = Pending {
            event,
            bytes: (0, 0),
            generation: self.generation,
        };
        // A new connection reuses the address and ports, so the previous one has ended.
        if let Some(previous) = self.pending.insert(key, pending) {
            self.finish(previous);
        }
    }

    /// Update traffic counters of connections in progress, and report the ones which have ended.
    fn poll_states(&mut self) {
        self.next_poll = Instant::now() + STATE_POLL_INTERVAL;
        match read_states(&self.pf) {
            Ok(states) => self.update_states(&states),
            Err(err) => warn!("Failed to read Packet Filter states: {err}"),
        }
    }

    /// Process the state table, an array of platform-specific state structures.
    fn update_states(&mut self, states: &[u8]) {
        self.generation += 1;
        for state in states.as_chunks::<STATE_SIZE>().0 {
            let Some(state) = parse_state(state) else {
                continue;
            };
            // Not all platforms record the interface on which states were created.
            if state.ifname.is_some_and(|ifname| ifname != self.ifname) {
                continue;
            }
            let (key, bytes) = (state.key, state.bytes);
            if let Some(pending) = self.pending.get_mut(&key) {
                pending.bytes = bytes;
                pending.generation = self.generation;
            }
        }

        let ended: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, pending)| pending.generation != self.generation)
            .map(|(key, _)| *key)
            .collect();
        for key in ended {
            if let Some(pending) = self.pending.remove(&key) {
                self.finish(pending);
            }
        }
    }

    /// Stop tracking the oldest connection in progress, and report it.
    fn forget_oldest(&mut self) {
        let Some(oldest) = self
            .pending
            .iter()
            .min_by_key(|(_, pending)| pending.event.timestamp)
            .map(|(key, _)| *key)
        else {
            return;
        };
        debug!("Too many tracked connections, reporting {oldest:?} early");
        if let Some(pending) = self.pending.remove(&oldest) {
            self.finish(pending);
        }
    }

    /// Report an ended connection with its traffic counters.
    fn finish(&self, pending: Pending) {
        let mut event = pending.event;
        let (initiator, responder) = pending.bytes;
        (event.upload_bytes, event.download_bytes) = match event.direction {
            TrafficDirection::Outbound => (initiator, responder),
            TrafficDirection::Inbound => (responder, initiator),
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

/// Fields of `struct pfloghdr` used by the monitor.
#[derive(Debug, PartialEq)]
struct PflogHeader<'a> {
    /// Header length, including padding.
    length: usize,
    action: u8,
    ifname: &'a str,
    ruleset: &'a str,
    /// Number of the matching rule within its anchor.
    rule_number: u32,
    dir: u8,
}

impl<'a> PflogHeader<'a> {
    fn parse(packet: &'a [u8]) -> Option<Self> {
        let length = usize::from(*packet.get(PFLOG_LENGTH)?).next_multiple_of(PFLOG_ALIGNMENT);
        if length <= PFLOG_DIR || packet.len() < length {
            return None;
        }
        Some(Self {
            length,
            action: packet[PFLOG_ACTION],
            ifname: c_str(&packet[PFLOG_IFNAME_OFFSET..PFLOG_RULESET]),
            ruleset: c_str(&packet[PFLOG_RULESET..PFLOG_RULESET + 16]),
            rule_number: u32::from_be_bytes(
                packet[PFLOG_SUBRULENR..PFLOG_SUBRULENR + 4]
                    .try_into()
                    .ok()?,
            ),
            dir: packet[PFLOG_DIR],
        })
    }
}

/// Fields of `struct bpf_hdr`.
struct BpfHeader {
    /// Header length, including padding.
    length: usize,
    /// Length of the captured packet.
    captured: usize,
    timestamp: SystemTime,
}

/// Connection details from a Packet Filter state.
struct State<'a> {
    /// Interface on which the state was created, if known.
    ifname: Option<&'a str>,
    key: FlowKey,
    /// Bytes sent by the initiator and the responder.
    bytes: (u64, u64),
}

/// Interpret a nul-terminated buffer as a string; empty if it's not valid UTF-8.
fn c_str(buf: &[u8]) -> &str {
    CStr::from_bytes_until_nul(buf)
        .ok()
        .and_then(|name| name.to_str().ok())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests;
