//! macOS specifics of the connection monitor.
//!
//! Source: https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/pfvar.h

use std::{
    fs::{File, OpenOptions},
    io,
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    ptr,
    time::{Duration, UNIX_EPOCH},
};

use defguard_wireguard_rs::bsd::ioctl::iowr;
use libc::{c_int, c_ulong, c_void};

use super::{BpfHeader, PF_OUT, State};
use crate::enterprise::firewall::flow::{FlowKey, ipv4, ipv6, protocol_has_ports};

/// BPF devices are `/dev/bpf0`, `/dev/bpf1`, and so on.
const MAX_BPF_DEVICES: u32 = 256;

pub(super) const PFLOG_HINT: &str = "Create it with `ifconfig pflog0 create`.";

// net/bpf.h
pub(super) const BPF_ALIGNMENT: usize = 4;
/// `struct bpf_hdr`: `struct timeval32` (two 32-bit fields), then lengths.
const BPF_CAPLEN: usize = 8;
const BPF_HDRLEN: usize = 16;

// net/pfvar.h: `struct pfsync_state` (packed) and offsets of its fields.
pub(super) const STATE_SIZE: usize = 297;
/// `struct pfsync_state_host`: `struct pf_addr`, then `union pf_state_xport`.
pub(super) const STATE_LAN: usize = 24;
pub(super) const STATE_EXT_LAN: usize = 72;
/// `bytes[2][2]`: each counter split into high and low 32 bits.
pub(super) const STATE_BYTES: usize = 260;
pub(super) const STATE_AF: usize = 282;
pub(super) const STATE_PROTO: usize = 284;
pub(super) const STATE_DIRECTION: usize = 285;

/// Equivalent to `struct pfioc_states`.
#[repr(C)]
struct IocStates {
    len: c_int,
    buf: *mut c_void,
}

const DIOCGETSTATES: c_ulong = iowr::<IocStates>(b'D', 25);

/// Open the first BPF device which isn't in use.
pub(super) fn open_bpf() -> io::Result<File> {
    for index in 0..MAX_BPF_DEVICES {
        match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC)
            .open(format!("/dev/bpf{index}"))
        {
            Ok(file) => return Ok(file),
            Err(err) if err.raw_os_error() == Some(libc::EBUSY) => {}
            Err(err) => return Err(err),
        }
    }
    Err(io::Error::from_raw_os_error(libc::EBUSY))
}

pub(super) fn parse_bpf_header(buf: &[u8]) -> Option<BpfHeader> {
    let field = |offset: usize, len: usize| buf.get(offset..offset + len);
    let secs = i32::from_ne_bytes(field(0, 4)?.try_into().ok()?);
    let usecs = i32::from_ne_bytes(field(4, 4)?.try_into().ok()?);
    Some(BpfHeader {
        length: usize::from(u16::from_ne_bytes(field(BPF_HDRLEN, 2)?.try_into().ok()?)),
        captured: u32::from_ne_bytes(field(BPF_CAPLEN, 4)?.try_into().ok()?) as usize,
        timestamp: UNIX_EPOCH
            + Duration::from_secs(secs as u64)
            + Duration::from_micros(usecs as u64),
    })
}

/// Parse `struct pfsync_state`.
pub(super) fn parse_state(state: &[u8; STATE_SIZE]) -> Option<State<'_>> {
    let af = i32::from(state[STATE_AF]);
    // ICMPv6 states are recorded as ICMP.
    let protocol = match (i32::from(state[STATE_PROTO]), af) {
        (libc::IPPROTO_ICMP, libc::AF_INET6) => libc::IPPROTO_ICMPV6 as u8,
        (protocol, _) => protocol as u8,
    };
    let addr = |host: usize| match af {
        libc::AF_INET => ipv4(&state[host..]),
        libc::AF_INET6 => ipv6(&state[host..]),
        _ => None,
    };
    let port = |host: usize| u16::from_be_bytes([state[host + 16], state[host + 17]]);
    // `lan` is the local side, `ext_lan` the remote one: for states created by incoming packets,
    // the remote side is the initiator.
    let (src, dst) = if state[STATE_DIRECTION] == PF_OUT {
        (STATE_LAN, STATE_EXT_LAN)
    } else {
        (STATE_EXT_LAN, STATE_LAN)
    };
    // Match the way connections are identified from packets: ICMP by identifier only, which is
    // always stored on the `lan` side.
    let (source_port, destination_port) = match i32::from(protocol) {
        libc::IPPROTO_ICMP | libc::IPPROTO_ICMPV6 => (port(STATE_LAN), 0),
        _ if protocol_has_ports(protocol) => (port(src), port(dst)),
        _ => (0, 0),
    };
    let counter = |index: usize| {
        let offset = STATE_BYTES + index * 8;
        let high = u32::from_ne_bytes(state[offset..offset + 4].try_into().unwrap_or_default());
        let low = u32::from_ne_bytes(state[offset + 4..offset + 8].try_into().unwrap_or_default());
        (u64::from(high) << 32) | u64::from(low)
    };
    Some(State {
        // States don't record the interface on which they were created.
        ifname: None,
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

/// Read the whole Packet Filter state table, as an array of `struct pfsync_state`.
pub(super) fn read_states(pf: &File) -> io::Result<Vec<u8>> {
    let mut ioc = IocStates {
        len: 0,
        buf: ptr::null_mut(),
    };
    // With zero length, the kernel reports the size needed for the current number of states.
    if unsafe { libc::ioctl(pf.as_raw_fd(), DIOCGETSTATES, &raw mut ioc) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // States may be added in the meantime, and the kernel silently truncates the list, so leave
    // plenty of room.
    let capacity = usize::try_from(ioc.len).unwrap_or_default() * 2 + 64 * STATE_SIZE;
    let mut buf = vec![0u8; capacity];
    ioc.len = c_int::try_from(capacity).unwrap_or(c_int::MAX);
    ioc.buf = buf.as_mut_ptr().cast();
    if unsafe { libc::ioctl(pf.as_raw_fd(), DIOCGETSTATES, &raw mut ioc) } < 0 {
        return Err(io::Error::last_os_error());
    }
    buf.truncate(usize::try_from(ioc.len).unwrap_or_default());
    Ok(buf)
}
