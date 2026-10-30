//! FreeBSD specifics of the connection monitor.

use std::{
    fs::{File, OpenOptions},
    io, mem,
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    ptr,
    time::{Duration, UNIX_EPOCH},
};

use defguard_wireguard_rs::bsd::ioctl::iowr;
use libc::{c_int, c_ulong, c_void};

use super::{BpfHeader, PF_OUT, State, c_str};
use crate::enterprise::firewall::flow::{FlowKey, ipv4, ipv6, protocol_has_ports};

const DEV_BPF: &str = "/dev/bpf";

pub(super) const PFLOG_HINT: &str =
    "Load the pflog module with `kldload pflog` or `pflog_enable=\"YES\"` in rc.conf.";

// net/bpf.h
pub(super) const BPF_ALIGNMENT: usize = mem::size_of::<libc::c_long>();
/// `struct bpf_hdr`: `struct timeval` (two 64-bit fields), then lengths.
const BPF_CAPLEN: usize = 16;
const BPF_HDRLEN: usize = 24;

// net/pfvar.h: `struct pf_state_export` and offsets of its fields.
const PF_STATE_VERSION: u64 = 20_230_404;
pub(super) const STATE_SIZE: usize = 384;
pub(super) const STATE_ORIG_IFNAME: usize = 32;
/// `key[PF_SK_WIRE]`: `addr[2]` followed by `port[2]`.
pub(super) const STATE_KEY: usize = 48;
pub(super) const STATE_BYTES: usize = 240;
pub(super) const STATE_AF: usize = 264;
pub(super) const STATE_PROTO: usize = 265;
pub(super) const STATE_DIRECTION: usize = 266;

/// Equivalent to `struct pfioc_states_v2`.
#[repr(C)]
struct IocStatesV2 {
    len: c_int,
    req_version: u64,
    buf: *mut c_void,
}

const DIOCGETSTATESV2: c_ulong = iowr::<IocStatesV2>(b'D', 93);

/// Open a BPF device; `/dev/bpf` hands out a new one on each open.
pub(super) fn open_bpf() -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC)
        .open(DEV_BPF)
}

pub(super) fn parse_bpf_header(buf: &[u8]) -> Option<BpfHeader> {
    let field = |offset: usize, len: usize| buf.get(offset..offset + len);
    let secs = i64::from_ne_bytes(field(0, 8)?.try_into().ok()?);
    let usecs = i64::from_ne_bytes(field(8, 8)?.try_into().ok()?);
    Some(BpfHeader {
        length: usize::from(u16::from_ne_bytes(field(BPF_HDRLEN, 2)?.try_into().ok()?)),
        captured: u32::from_ne_bytes(field(BPF_CAPLEN, 4)?.try_into().ok()?) as usize,
        timestamp: UNIX_EPOCH
            + Duration::from_secs(secs as u64)
            + Duration::from_micros(usecs as u64),
    })
}

/// Parse `struct pf_state_export`.
pub(super) fn parse_state(state: &[u8; STATE_SIZE]) -> Option<State<'_>> {
    let protocol = state[STATE_PROTO];
    let addr = |index: usize| {
        let data = &state[STATE_KEY + index * 16..];
        match i32::from(state[STATE_AF]) {
            libc::AF_INET => ipv4(data),
            libc::AF_INET6 => ipv6(data),
            _ => None,
        }
    };
    let port = |index: usize| {
        let offset = STATE_KEY + 32 + index * 2;
        u16::from_be_bytes([state[offset], state[offset + 1]])
    };
    // The key is ordered by the direction in which the state was created.
    let (src, dst) = if state[STATE_DIRECTION] == PF_OUT {
        (1, 0)
    } else {
        (0, 1)
    };
    // Match the way connections are identified from packets: ICMP by identifier only.
    let (source_port, destination_port) = match i32::from(protocol) {
        libc::IPPROTO_ICMP | libc::IPPROTO_ICMPV6 => (port(src), 0),
        _ if protocol_has_ports(protocol) => (port(src), port(dst)),
        _ => (0, 0),
    };
    let counter = |index: usize| {
        let offset = STATE_BYTES + index * 8;
        u64::from_ne_bytes(state[offset..offset + 8].try_into().unwrap_or_default())
    };
    Some(State {
        ifname: Some(c_str(&state[STATE_ORIG_IFNAME..])),
        key: FlowKey {
            protocol,
            source: addr(src)?,
            destination: addr(dst)?,
            source_port,
            destination_port,
        },
        bytes: (counter(0), counter(1)),
    })
}

/// Read the whole Packet Filter state table, as an array of `struct pf_state_export`.
pub(super) fn read_states(pf: &File) -> io::Result<Vec<u8>> {
    let mut ioc = IocStatesV2 {
        len: 0,
        req_version: PF_STATE_VERSION,
        buf: ptr::null_mut(),
    };
    // With zero length, the kernel reports the size needed for the current number of states.
    if unsafe { libc::ioctl(pf.as_raw_fd(), DIOCGETSTATESV2, &raw mut ioc) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // States may be added in the meantime, and the kernel silently truncates the list, so leave
    // plenty of room.
    let capacity = usize::try_from(ioc.len).unwrap_or_default() * 2 + 64 * STATE_SIZE;
    let mut buf = vec![0u8; capacity];
    ioc.len = c_int::try_from(capacity).unwrap_or(c_int::MAX);
    ioc.buf = buf.as_mut_ptr().cast();
    if unsafe { libc::ioctl(pf.as_raw_fd(), DIOCGETSTATESV2, &raw mut ioc) } < 0 {
        return Err(io::Error::last_os_error());
    }
    buf.truncate(usize::try_from(ioc.len).unwrap_or_default());
    Ok(buf)
}
