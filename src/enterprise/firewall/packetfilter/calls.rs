//! Low level communication with Packet Filter.

use std::{
    ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_ulong, c_ushort, c_void},
    fmt,
    mem::{MaybeUninit, size_of, zeroed},
    ptr,
};

use ipnetwork::IpNetwork;
use libc::{IFNAMSIZ, pid_t, uid_t};
use nix::{ioctl_none, ioctl_readwrite};

use super::rule::{Action, AddressFamily, Direction, PacketFilterRule, RuleSet, State};
use crate::enterprise::firewall::Port;

/// Equivalent to `struct pf_addr`: fits 128-bit address, either IPv4 or IPv6.
type Addr = [u8; 16]; // Do not use u128 for the sake of alignment.
/// Equivalent to `pf_poolhashkey`: 128-bit hash key.
type PoolHashKey = [u8; 16];

/// Equivalent to `struct pf_addr_wrap_addr_mask`.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
struct AddrMask {
    addr: Addr,
    mask: Addr,
}

impl From<IpNetwork> for AddrMask {
    fn from(ip_network: IpNetwork) -> Self {
        match ip_network {
            IpNetwork::V4(ipnet4) => {
                let mut addr_mask = Self {
                    addr: [0; 16],
                    mask: [0; 16],
                };
                // Fill the first 4 bytes of `addr` and `mask`.
                addr_mask.addr[..4].copy_from_slice(&ipnet4.ip().octets());
                addr_mask.mask[..4].copy_from_slice(&ipnet4.mask().octets());

                addr_mask
            }

            IpNetwork::V6(ipnet6) => Self {
                addr: ipnet6.ip().octets(),
                mask: ipnet6.mask().octets(),
            },
        }
    }
}

union VTarget {
    a: AddrMask,
    ifname: [u8; IFNAMSIZ],
    // tblname: [u8; 32],
    // rtlabelname: [u8; 32],
    // rtlabel: c_uint,
}

// const PFI_AFLAG_NETWORK: u8 = 1;
// const PFI_AFLAG_BROADCAST: u8 = 2;
// const PFI_AFLAG_PEER: u8 = 4;
// const PFI_AFLAG_MODEMASK: u8 = 7;
// const PFI_AFLAG_NOALIAS: u8 = 8;

/// Equivalent to `struct pf_addr_wrap`.
/// Only the `v` part of the union, as `p` is not used in this crate.
#[repr(C)]
struct AddrWrap {
    v: VTarget,
    // Unused in this crate.
    p: u64,
    // Determines type of field `v`.
    r#type: AddrType,
    // See PFI_AFLAG
    iflags: u8,
}

#[allow(dead_code)]
#[derive(Debug)]
#[repr(u8)]
pub enum AddrType {
    // PF_ADDR_ADDRMASK = 0,
    AddrMask,
    // PF_ADDR_NOROUTE = 1,
    NoRoute,
    // PF_ADDR_DYNIFTL = 2,
    DynIftl,
    // PF_ADDR_TABLE = 3,
    Table,
    // Values below differ on macOS and FreeBSD.
    // PF_ADDR_RTLABEL = 4,
    // RtLabel,
    // // PF_ADDR_URPFFAILED = 5,
    // UrpfFailed,
    // // PF_ADDR_RANGE = 6,
    // Range,
}

impl AddrWrap {
    #[must_use]
    fn with_network(ip_network: IpNetwork) -> Self {
        Self {
            v: VTarget {
                a: ip_network.into(),
            },
            p: 0,
            r#type: AddrType::AddrMask,
            iflags: 0,
        }
    }

    #[allow(dead_code)]
    #[must_use]
    fn with_interface(ifname: &str) -> Self {
        let mut uninit = MaybeUninit::<Self>::zeroed();
        let len = ifname.len().min(IFNAMSIZ - 1);
        unsafe {
            let self_ptr = &mut *uninit.as_mut_ptr();
            self_ptr.v.ifname[..len].copy_from_slice(&ifname.as_bytes()[..len]);
            // Probably, this is needed only for pfctl to omit displaying number of bits.
            // FIXME: Fill all bytes for IPv6.
            self_ptr.v.a.mask[..4].fill(255);
            self_ptr.r#type = AddrType::DynIftl;
        }

        unsafe { uninit.assume_init() }
    }
}

impl fmt::Debug for AddrWrap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("AddrWrap");
        match self.r#type {
            AddrType::AddrMask => {
                debug.field("v.a", unsafe { &self.v.a });
            }
            AddrType::DynIftl => {
                debug.field("v.ifname", unsafe { &self.v.ifname });
            }
            _ => (),
        }
        debug.field("p", &self.p);
        debug.field("type", &self.r#type);
        debug.field("iflags", &self.iflags);
        debug.finish()
    }
}

/// Equivalent to `struct pf_rule_addr`.
#[derive(Debug)]
#[repr(C)]
pub(super) struct RuleAddr {
    addr: AddrWrap,
    // macOS: here `union pf_rule_xport` is flattened to its first variant: `struct pf_port_range`.
    port: [c_ushort; 2],
    #[cfg(any(target_os = "freebsd", target_os = "macos"))]
    op: PortOp,
    #[cfg(target_os = "macos")]
    _padding: [c_uchar; 3],
    #[cfg(any(target_os = "macos", target_os = "netbsd"))]
    neg: c_uchar,
    #[cfg(target_os = "netbsd")]
    op: PortOp,
}

impl RuleAddr {
    #[must_use]
    pub(super) fn new(ip_network: IpNetwork, port: Port) -> Self {
        let addr = AddrWrap::with_network(ip_network);
        let from_port;
        let to_port;
        let op;
        match port {
            Port::Any => {
                from_port = 0;
                to_port = 0;
                op = PortOp::None;
            }
            Port::Single(port) => {
                from_port = port;
                to_port = 0;
                op = PortOp::None;
            }
            Port::Range(from, to) => {
                from_port = from;
                to_port = to;
                op = PortOp::Equal;
            }
        }
        Self {
            addr,
            port: [from_port, to_port],
            op,
            #[cfg(target_os = "macos")]
            _padding: [0; 3],
            #[cfg(any(target_os = "macos", target_os = "netbsd"))]
            neg: 0,
        }
    }
}

#[derive(Debug)]
#[repr(C)]
struct TailQueue<T> {
    tqh_first: *mut T,
    tqh_last: *mut *mut T,
}

impl<T> TailQueue<T> {
    fn init(&mut self) {
        self.tqh_first = ptr::null_mut();
        self.tqh_last = &raw mut self.tqh_first;
    }
}

#[derive(Debug)]
#[repr(C)]
struct TailQueueEntry<T> {
    tqe_next: *mut T,
    tqe_prev: *mut *mut T,
}

/// Equivalent to `struct pf_pooladdr`.
#[derive(Debug)]
#[repr(C)]
pub struct PoolAddr {
    addr: AddrWrap,
    entries: TailQueueEntry<Self>,
    ifname: [u8; IFNAMSIZ],
    kif: usize, // *mut c_void,
}

impl PoolAddr {
    #[allow(dead_code)]
    #[must_use]
    pub fn with_network(ip_network: IpNetwork) -> Self {
        Self {
            addr: AddrWrap::with_network(ip_network),
            entries: unsafe { zeroed::<TailQueueEntry<Self>>() },
            ifname: [0; IFNAMSIZ],
            kif: 0,
        }
    }

    #[allow(dead_code)]
    #[must_use]
    pub fn with_interface(ifname: &str) -> Self {
        Self {
            addr: AddrWrap::with_interface(ifname),
            entries: unsafe { zeroed::<TailQueueEntry<Self>>() },
            ifname: [0; IFNAMSIZ],
            kif: 0,
        }
    }
}

#[allow(dead_code)]
#[derive(Debug)]
#[repr(u8)]
pub(super) enum PoolOpts {
    /// PF_POOL_NONE = 0
    None,
    /// PF_POOL_BITMASK = 1
    BitMask,
    /// PF_POOL_RANDOM = 2
    Random,
    /// PF_POOL_SRCHASH = 3
    SrcHash,
    /// PF_POOL_ROUNDROBIN = 4
    RoundRobin,
}

/// Equivalent to `struct pf_pool`.
#[derive(Debug)]
#[repr(C)]
pub(super) struct Pool {
    list: TailQueue<PoolAddr>,
    cur: *mut PoolAddr,
    key: PoolHashKey,
    counter: Addr,
    tblidx: c_int,
    pub(super) proxy_port: [c_ushort; 2],
    #[cfg(any(target_os = "macos", target_os = "netbsd"))]
    port_op: PortOp,
    pub(super) opts: PoolOpts,
    #[cfg(target_os = "macos")]
    af: AddressFamily,
}

#[allow(dead_code)]
#[derive(Debug)]
#[repr(u8)]
enum PortOp {
    /// PF_OP_NONE = 0
    None,
    /// PF_OP_IRG = 1
    InclRange, // ((p > a1) && (p < a2))
    /// PF_OP_EQ = 2
    Equal,
    /// PF_OP_NE = 3,
    NotEqual,
    /// PF_OP_LT = 4
    Less,
    /// PF_OP_LE = 5
    LessOrEqual,
    /// PF_OP_GT = 6
    Greater,
    /// PF_OP_GE = 7
    GreaterOrEqual = 7,
    /// PF_OP_XRG = 8
    ExclRange, // ((p < a1) || (p > a2))
    /// PF_OP_RRG = 9
    Range = 9, // ((p >= a1) && (p <= a2))
}

#[allow(dead_code)]
impl Pool {
    #[must_use]
    pub(super) fn new(from_port: u16, to_port: u16) -> Self {
        let mut uninit = MaybeUninit::<Self>::zeroed();
        let self_ptr = uninit.as_mut_ptr();
        unsafe {
            (*self_ptr).proxy_port[0] = from_port;
            (*self_ptr).proxy_port[1] = to_port;
        }

        unsafe { uninit.assume_init() }
    }

    /// Insert `PoolAddr` at the end of the list. Take ownership of the given `PoolAddr`.
    pub(super) fn insert_pool_addr(&mut self, mut pool_addr: PoolAddr) {
        // TODO: Traverse tail queue; for now assume empty tail queue.
        assert!(
            self.list.tqh_first.is_null(),
            "Expected one entry in PoolAddr TailQueue."
        );
        self.list.tqh_first = &raw mut pool_addr;
        self.list.tqh_last = &raw mut pool_addr.entries.tqe_next;
        pool_addr.entries.tqe_next = ptr::null_mut();
        pool_addr.entries.tqe_prev = &raw mut self.list.tqh_first;
    }
}

impl Drop for Pool {
    // `Pool` owns the list of `PoolAddr`, so drop them here.
    fn drop(&mut self) {
        let mut next = self.list.tqh_first;
        while !next.is_null() {
            unsafe {
                next = (*next).entries.tqe_next;
                ptr::drop_in_place(self.list.tqh_first);
            }
        }
    }
}

#[repr(C)]
struct pf_anchor_node {
    rbe_left: *mut pf_anchor,
    rbe_right: *mut pf_anchor,
    rbe_parent: *mut pf_anchor,
}

#[repr(C)]
struct pf_ruleset_rule {
    ptr: *mut TailQueue<Rule>,
    ptr_array: *mut *mut Rule,
    rcount: c_uint,
    rsize: c_uint,
    ticket: c_uint,
    open: c_int,
}

#[repr(C)]
struct pf_ruleset_rules {
    queues: [TailQueue<Rule>; 2],
    active: pf_ruleset_rule,
    inactive: pf_ruleset_rule,
}

#[repr(C)]
struct pf_ruleset {
    rules: [pf_ruleset_rules; 6],
    anchor: *mut pf_anchor,
    tticket: c_uint,
    tables: c_int,
    topen: c_int,
}

#[repr(C)]
struct pf_anchor {
    entry_global: pf_anchor_node,
    entry_node: pf_anchor_node,
    parent: *mut pf_anchor,
    children: pf_anchor_node,
    name: [c_char; 64],
    path: [c_char; MAXPATHLEN],
    ruleset: pf_ruleset,
    refcnt: c_int,
    match_: c_int,
    owner: [c_char; 64],
}

#[derive(Debug)]
#[repr(C)]
struct pf_rule_conn_rate {
    limit: c_uint,
    seconds: c_uint,
}

#[derive(Debug)]
#[repr(C)]
struct pf_rule_id {
    uid: [uid_t; 2],
    op: c_uchar,
    //_pad: [u_int8_t; 3],
}

/// As defined in `net/pfvar.h`.
const PF_RULE_LABEL_SIZE: usize = 64;

/// Equivalent to 'struct pf_rule'.
#[derive(Debug)]
#[repr(C)]
pub(super) struct Rule {
    src: RuleAddr,
    dst: RuleAddr,

    skip: [usize; 8],
    label: [c_uchar; PF_RULE_LABEL_SIZE],
    ifname: [c_uchar; IFNAMSIZ],
    qname: [c_uchar; 64],
    pqname: [c_uchar; 64],
    tagname: [c_uchar; 64],
    match_tagname: [c_uchar; 64],
    overload_tblname: [c_uchar; 32],

    entries: TailQueueEntry<Self>,
    pub(super) rpool: Pool,

    evaluations: c_long,
    packets: [c_ulong; 2],
    bytes: [c_ulong; 2],

    #[cfg(target_os = "macos")]
    ticket: c_ulong,
    #[cfg(target_os = "macos")]
    owner: [c_char; 64],
    #[cfg(target_os = "macos")]
    priority: c_int,

    kif: *mut c_void, // struct pfi_kif, kernel only
    anchor: *mut pf_anchor,
    overload_tbl: *mut c_void, // struct pfr_ktable, kernel only

    os_fingerprint: c_uint,

    rtableid: c_int,
    #[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
    timeout: [c_uint; 20],
    #[cfg(target_os = "macos")]
    timeout: [c_uint; 26],
    #[cfg(any(target_os = "macos", target_os = "netbsd"))]
    states: c_uint,
    max_states: c_uint,
    #[cfg(any(target_os = "macos", target_os = "netbsd"))]
    src_nodes: c_uint,
    max_src_nodes: c_uint,
    max_src_states: c_uint,
    max_src_conn: c_uint,
    max_src_conn_rate: pf_rule_conn_rate,
    qid: c_uint,
    pqid: c_uint,
    rt_listid: c_uint,
    nr: c_uint,
    prob: c_uint,
    cuid: uid_t,
    cpid: pid_t,

    #[cfg(target_os = "freebsd")]
    states_cur: u64,
    #[cfg(target_os = "freebsd")]
    states_tot: u64,
    #[cfg(target_os = "freebsd")]
    src_nodes: u64,

    return_icmp: c_ushort,
    return_icmp6: c_ushort,
    max_mss: c_ushort,
    tag: c_ushort,
    match_tag: c_ushort,
    #[cfg(target_os = "freebsd")]
    scrub_flags: c_ushort,

    uid: pf_rule_id,
    gid: pf_rule_id,

    rule_flag: c_uint, // RuleFlag
    pub(super) action: Action,
    direction: Direction,
    log: c_uchar, // LogFlags
    logif: c_uchar,
    quick: bool,
    ifnot: c_uchar,
    match_tag_not: c_uchar,
    natpass: c_uchar,

    keep_state: State,
    af: AddressFamily,
    proto: c_uchar,
    r#type: c_uchar,
    code: c_uchar,
    flags: c_uchar,   // TCP_FLAG
    flagset: c_uchar, // TCP_FLAG
    min_ttl: c_uchar,
    allow_opts: c_uchar,
    rt: c_uchar,
    return_ttl: c_uchar,

    tos: c_uchar,
    #[cfg(target_os = "freebsd")]
    set_tos: c_uchar,
    anchor_relative: c_uchar,
    anchor_wildcard: c_uchar,
    flush: c_uchar,
    #[cfg(target_os = "freebsd")]
    prio: c_uchar,
    #[cfg(target_os = "freebsd")]
    set_prio: [c_uchar; 2],

    #[cfg(target_os = "freebsd")]
    divert: (Addr, u16),

    #[cfg(target_os = "freebsd")]
    u_states_cur: u64,
    #[cfg(target_os = "freebsd")]
    u_states_tot: u64,
    #[cfg(target_os = "freebsd")]
    u_src_nodes: u64,

    #[cfg(target_os = "macos")]
    proto_variant: c_uchar,
    #[cfg(target_os = "macos")]
    extfilter: c_uchar,
    #[cfg(target_os = "macos")]
    extmap: c_uchar,
    #[cfg(target_os = "macos")]
    dnpipe: c_uint,
    #[cfg(target_os = "macos")]
    dntype: c_uint,
}

impl Rule {
    pub(super) fn from_pf_rule(pf_rule: &PacketFilterRule) -> Self {
        let mut uninit = MaybeUninit::<Self>::zeroed();

        unsafe {
            let self_ptr = &mut *uninit.as_mut_ptr();

            if let Some(from) = pf_rule.from {
                self_ptr.src = RuleAddr::new(from, pf_rule.from_port);
            }
            if let Some(to) = pf_rule.to {
                self_ptr.dst = RuleAddr::new(to, pf_rule.to_port);
            }
            if let Some(interface) = &pf_rule.interface {
                let len = interface.len().min(IFNAMSIZ - 1);
                self_ptr.ifname[..len].copy_from_slice(&interface.as_bytes()[..len]);
            }
            if let Some(label) = &pf_rule.label {
                let len = label.len().min(PF_RULE_LABEL_SIZE - 1);
                self_ptr.label[..len].copy_from_slice(&label.as_bytes()[..len]);
            }

            // Don't use routing tables.
            #[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
            {
                self_ptr.rtableid = -1;
            }
            #[cfg(target_os = "macos")]
            {
                self_ptr.rtableid = 0;
            }

            self_ptr.action = pf_rule.action;
            self_ptr.direction = pf_rule.direction;
            self_ptr.log = pf_rule.log;
            self_ptr.quick = pf_rule.quick;

            self_ptr.keep_state = pf_rule.state;
            let af = pf_rule.address_family();
            self_ptr.af = af;
            #[cfg(target_os = "macos")]
            {
                self_ptr.rpool.af = af;
            }
            self_ptr.proto = pf_rule.proto as u8;
            self_ptr.flags = pf_rule.tcp_flags;
            self_ptr.flagset = pf_rule.tcp_flags_set;

            self_ptr.rpool.list.init();

            uninit.assume_init()
        }
    }
}

/// Equivalent to PF_CHANGE_... enum.
#[allow(dead_code)]
#[repr(u32)]
pub(crate) enum Change {
    // PF_CHANGE_NONE = 0
    None,
    // PF_CHANGE_ADD_HEAD = 1
    AddHead,
    // PF_CHANGE_ADD_TAIL = 2
    AddTail,
    // PF_CHANGE_ADD_BEFORE = 3
    AddBefore,
    // PF_CHANGE_ADD_AFTER = 4
    AddAfter,
    // PF_CHANGE_REMOVE = 5
    Remove,
    // PF_CHANGE_GET_TICKET = 6
    GetTicket,
}

/// Rule flags, equivalent to PFRULE_...
#[allow(dead_code)]
#[repr(u32)]
pub(crate) enum RuleFlag {
    Drop = 0,
    ReturnRST = 1,
    Fragment = 2,
    ReturnICMP = 4,
    Return = 8,
    NoSync = 16,
    SrcTrack = 32,
    RuleSrcTrack = 64,
    // ...
}

pub(crate) const MAXPATHLEN: usize = libc::PATH_MAX as usize;

/// Equivalent to `struct pfioc_rule`.
#[repr(C)]
pub(super) struct IocRule {
    pub action: Change,
    pub ticket: c_uint,
    pub pool_ticket: c_uint,
    pub nr: c_uint,
    pub anchor: [c_uchar; MAXPATHLEN],
    pub anchor_call: [c_uchar; MAXPATHLEN],
    pub rule: Rule,
}

impl IocRule {
    #[must_use]
    pub(super) fn with_rule(anchor: &str, rule: Rule) -> Self {
        let mut uninit = MaybeUninit::<Self>::zeroed();

        // Copy anchor name.
        let len = anchor.len().min(MAXPATHLEN - 1);
        unsafe {
            let self_ptr = &mut *uninit.as_mut_ptr();
            self_ptr.anchor[..len].copy_from_slice(&anchor.as_bytes()[..len]);
            self_ptr.rule = rule;
        }

        unsafe { uninit.assume_init() }
    }
}

/// Equivalent to `struct pfioc_pooladdr`.
#[repr(C)]
pub(super) struct IocPoolAddr {
    action: Change,
    pub(super) ticket: c_uint,
    nr: c_uint,
    r_num: c_uint,
    r_action: c_uchar,
    r_last: c_uchar,
    af: c_uchar,
    anchor: [c_uchar; MAXPATHLEN],
    addr: PoolAddr,
}

impl IocPoolAddr {
    #[must_use]
    pub(super) fn new(anchor: &str) -> Self {
        let mut uninit = MaybeUninit::<Self>::zeroed();

        // Copy anchor name.
        let len = anchor.len().min(MAXPATHLEN - 1);
        unsafe {
            let self_ptr = &mut *uninit.as_mut_ptr();
            self_ptr.anchor[..len].copy_from_slice(&anchor.as_bytes()[..len]);
        }

        unsafe { uninit.assume_init() }
    }

    #[allow(dead_code)]
    #[must_use]
    pub(super) fn with_pool_addr(addr: PoolAddr, ticket: c_uint) -> Self {
        let mut uninit = MaybeUninit::<Self>::zeroed();
        unsafe {
            let self_ptr = &mut *uninit.as_mut_ptr();
            self_ptr.ticket = ticket;
            self_ptr.addr = addr;
        }

        unsafe { uninit.assume_init() }
    }
}

/// Equivalent to `struct pfioc_trans_pfioc_trans_e`.
#[repr(C)]
pub(super) struct IocTransElement {
    rs_num: RuleSet,
    anchor: [c_uchar; MAXPATHLEN],
    pub(super) ticket: c_uint,
}

impl IocTransElement {
    #[must_use]
    pub(super) fn new(ruleset: RuleSet, anchor: &str) -> Self {
        let mut uninit = MaybeUninit::<Self>::zeroed();

        // Copy anchor name.
        let len = anchor.len().min(MAXPATHLEN - 1);
        unsafe {
            let self_ptr = &mut *uninit.as_mut_ptr();
            self_ptr.rs_num = ruleset;
            self_ptr.anchor[..len].copy_from_slice(&anchor.as_bytes()[..len]);
        }

        unsafe { uninit.assume_init() }
    }
}

/// Equivalent to `struct pfioc_trans`.
#[repr(C)]
pub(super) struct IocTrans {
    /// Number of elements.
    size: c_int,
    /// Size of each element in bytes.
    esize: c_int,
    array: *mut IocTransElement,
}

impl IocTrans {
    #[must_use]
    pub(super) fn new(elements: &mut [IocTransElement]) -> Self {
        Self {
            size: elements.len() as i32,
            esize: size_of::<IocTransElement>() as i32,
            array: elements.as_mut_ptr(),
        }
    }
}

// DIOCSTART
// Start the packet filter.
ioctl_none!(pf_start, b'D', 1);

// DIOCSTOP
// Stop the packet filter.
ioctl_none!(pf_stop, b'D', 2);

// DIOCADDRULE
// Add rule at the end of the inactive ruleset. This call requires a ticket obtained through
// a preceding DIOCXBEGIN call and a pool_ticket obtained through a DIOCBEGINADDRS call.
// DIOCADDADDR must also be called if any pool addresses are required. The optional anchor name
// indicates the anchor in which to append the rule. `nr` and `action` are ignored.
ioctl_readwrite!(pf_add_rule, b'D', 4, IocRule);

// DIOCGETRULES
ioctl_readwrite!(pf_get_rules, b'D', 6, IocRule);

// DIOCGETRULE
ioctl_readwrite!(pf_get_rule, b'D', 7, IocRule);

// DIOCCLRSTATES
// ioctl_readwrite!(pf_clear_states, b'D', 18, pfioc_state_kill);

// DIOCGETSTATUS
// ioctl_readwrite!(pf_get_status, b'D', 21, pf_status);

// DIOCGETSTATES (COMPAT_FREEBSD14)
// ioctl_readwrite!(pf_get_states, b'D', 25, pfioc_states);

// DIOCCHANGERULE
ioctl_readwrite!(pf_change_rule, b'D', 26, IocRule);

// DIOCINSERTRULE
// Substituted on FreeBSD, NetBSD, and OpenBSD by DIOCCHANGERULE with rule.action = PF_CHANGE_REMOVE
#[cfg(target_os = "macos")]
ioctl_readwrite!(pf_insert_rule, b'D', 27, IocRule);

// DIOCDELETERULE
// Substituted on FreeBSD, NetBSD, and OpenBSD by DIOCCHANGERULE with rule.action = PF_CHANGE_REMOVE
#[cfg(target_os = "macos")]
ioctl_readwrite!(pf_delete_rule, b'D', 28, IocRule);

// DIOCKILLSTATES
// ioctl_readwrite!(pf_kill_states, b'D', 41, pfioc_state_kill);

// DIOCBEGINADDRS
// Clear the buffer address pool and get a ticket for subsequent DIOCADDADDR, DIOCADDRULE, and
// DIOCCHANGERULE calls.
ioctl_readwrite!(pf_begin_addrs, b'D', 51, IocPoolAddr);

// DIOCADDADDR
// Add the pool address `addr` to the buffer address pool to be used in the following DIOCADDRULE
// or DIOCCHANGERULE call. All other members of the structure are ignored.
ioctl_readwrite!(pf_add_addr, b'D', 52, IocPoolAddr);

// DIOCGETADDRS
// Get a ticket for subsequent DIOCGETADDR calls and the number nr of pool addresses in the rule
// specified with r_action, r_num, and anchor.
ioctl_readwrite!(pf_get_addrs, b'D', 53, IocPoolAddr);

// DIOCGETADDR
// Get the pool address addr by its number nr from the rule specified with r_action, r_num, and
// anchor using the ticket obtained through a preceding DIOCGETADDRS call.
ioctl_readwrite!(pf_get_addr, b'D', 54, IocPoolAddr);

// DIOCCHANGEADDR
// ioctl_readwrite!(pf_change_addr, b'D', 55, IocPoolAddr);

// DIOCGETRULESETS
// ioctl_readwrite!(pf_get_rulesets, b'D', 58, PFRuleset);

// DIOCGETRULESET
// ioctl_readwrite!(pf_get_ruleset, b'D', 59, PFRuleset);

// DIOCXBEGIN
ioctl_readwrite!(pf_begin, b'D', 81, IocTrans);

// DIOCXCOMMIT
ioctl_readwrite!(pf_commit, b'D', 82, IocTrans);

// DIOCXROLLBACK
ioctl_readwrite!(pf_rollback, b'D', 83, IocTrans);

#[cfg(test)]
mod tests {
    use ipnetwork::{Ipv4Network, Ipv6Network};

    use std::{
        mem::align_of,
        net::{Ipv4Addr, Ipv6Addr},
    };

    use super::*;

    #[test]
    fn check_align_and_size() {
        assert_eq!(align_of::<AddrWrap>(), 8);
        assert_eq!(size_of::<AddrWrap>(), 48);

        assert_eq!(align_of::<Pool>(), 8);
        assert_eq!(size_of::<Pool>(), 72);

        assert_eq!(align_of::<IocTrans>(), 8);
        assert_eq!(size_of::<IocTrans>(), 16);

        assert_eq!(align_of::<IocTransElement>(), 4);
        assert_eq!(size_of::<IocTransElement>(), 1032);

        assert_eq!(align_of::<Rule>(), 8);
        #[cfg(target_os = "freebsd")]
        assert_eq!(size_of::<Rule>(), 976);
        #[cfg(target_os = "macos")]
        assert_eq!(size_of::<Rule>(), 1040);

        assert_eq!(align_of::<RuleAddr>(), 8);
        #[cfg(target_os = "freebsd")]
        assert_eq!(size_of::<RuleAddr>(), 56);
        #[cfg(target_os = "macos")]
        assert_eq!(size_of::<RuleAddr>(), 64);
        #[cfg(target_os = "netbsd")]
        assert_eq!(size_of::<RuleAddr>(), 56);

        assert_eq!(align_of::<IocRule>(), 8);
        #[cfg(target_os = "freebsd")]
        assert_eq!(size_of::<IocRule>(), 3040);
        #[cfg(target_os = "macos")]
        assert_eq!(size_of::<IocRule>(), 3104);
        #[cfg(target_os = "netbsd")]
        assert_eq!(size_of::<IocRule>(), 2976);
    }

    #[test]
    fn check_addr_mask() {
        let ipnetv4 = IpNetwork::V4(Ipv4Network::new(Ipv4Addr::LOCALHOST, 8).unwrap());

        let addr_mask = AddrMask::from(ipnetv4);
        assert_eq!(
            addr_mask.addr,
            [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            addr_mask.mask,
            [255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );

        let ipv6 = IpNetwork::V6(Ipv6Network::new(Ipv6Addr::LOCALHOST, 32).unwrap());
        let addr_wrap = AddrMask::from(ipv6);
        assert_eq!(
            addr_wrap.addr,
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );
        assert_eq!(
            addr_wrap.mask,
            [255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }
}
