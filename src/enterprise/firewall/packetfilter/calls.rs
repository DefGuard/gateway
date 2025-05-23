//! Low level communication with Packet Filter.

use std::{
    ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_ulong, c_ushort, c_void},
    mem::{size_of, MaybeUninit},
};

use ipnetwork::IpNetwork;
use libc::{pid_t, uid_t, IFNAMSIZ};
use nix::{ioctl_none, ioctl_readwrite};

use super::rule::{Action, AddressFamily, Direction, PacketFilterRule, RuleSet, State};
use crate::enterprise::firewall::Port;

/// Equivalent to `struct pf_addr`: fits 128-bit address, either IPv4 or IPv6.
type Addr = [u8; 16]; // Do not use u128 for the sake of alignment.
/// Equivalent to `pf_poolhashkey`: 128-bit hash key.
type PoolHashKey = [u8; 16];

/// Equivalent to `struct pf_addr_wrap_addr_mask`.
#[derive(Debug)]
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

/// Equivalent to `struct pf_addr_wrap`.
/// Only the `v` part of the union, as `p` is not used in this crate.
#[derive(Debug)]
#[repr(C)]
struct AddrWrap {
    v: AddrMask,
    // unused in this crate
    p: u64,
    r#type: AddrType,
    iflags: c_uchar,
}

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
    // Below differs on macOS and FreeBSD.
    // PF_ADDR_RTLABEL = 4,
    // RtLabel,
    // // PF_ADDR_URPFFAILED = 5,
    // UrpfFailed,
    // // PF_ADDR_RANGE = 6,
    // Range,
}

impl AddrWrap {
    #[must_use]
    pub fn new(ip_network: IpNetwork) -> Self {
        Self {
            v: ip_network.into(),
            p: 0,
            r#type: AddrType::AddrMask,
            iflags: 0,
        }
    }
}

/// Equivalent to `struct pf_rule_addr`.
#[derive(Debug)]
#[repr(C)]
pub(super) struct RuleAddr {
    addr: AddrWrap,
    // macOS: here `union pf_rule_xport` is flattened to its first variant: `struct pf_port_range`.
    port: [c_ushort; 2],
    op: PortOp,
    #[cfg(target_os = "macos")]
    _padding: [c_uchar; 3],
    #[cfg(target_os = "macos")]
    neg: c_uchar,
}

impl RuleAddr {
    #[must_use]
    pub(super) fn new(ip_network: IpNetwork, port: Port) -> Self {
        let addr = AddrWrap::new(ip_network);
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
            #[cfg(target_os = "macos")]
            neg: 0,
        }
    }
}

/// TAILQ_ENTRY
#[derive(Debug)]
#[repr(C)]
struct pf_rule_list {
    tqe_next: *mut Rule,
    tqe_prev: *mut *mut Rule,
}

#[derive(Debug)]
#[repr(C)]
struct pf_pooladdr_list {
    tqe_next: *mut PoolAddr,
    tqe_prev: *mut *mut PoolAddr,
}

// Equivalent to `struct pf_pooladdr`.
#[repr(C)]
pub struct PoolAddr {
    addr: AddrWrap,
    entries: pf_pooladdr_list,
    ifname: [u8; IFNAMSIZ],
    kif: usize, // *mut c_void,
}

impl PoolAddr {
    #[must_use]
    pub fn new(ip_network: IpNetwork, if_name: &str) -> Self {
        let mut ifname = [0; IFNAMSIZ];
        let len = if_name.len().min(IFNAMSIZ - 1);
        ifname[..len].copy_from_slice(&if_name.as_bytes()[..len]);
        Self {
            addr: AddrWrap::new(ip_network),
            entries: unsafe { std::mem::zeroed::<pf_pooladdr_list>() },
            ifname,
            kif: 0,
        }
    }
}

/// Equivalent to `struct pf_pool`.
#[derive(Debug)]
#[repr(C)]
pub(super) struct Pool {
    list: pf_pooladdr_list,
    cur: *mut c_void,
    key: PoolHashKey,
    counter: Addr,
    tblidx: c_int,
    proxy_port: [c_ushort; 2],
    #[cfg(target_os = "macos")]
    port_op: PortOp,
    opts: c_uchar,
    #[cfg(target_os = "macos")]
    af: AddressFamily, // sa_family_t,
}

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

impl Pool {
    #[must_use]
    pub fn new(port: u16) -> Self {
        let mut uninit = MaybeUninit::<Self>::zeroed();
        let self_ptr = uninit.as_mut_ptr();
        unsafe {
            (*self_ptr).proxy_port[0] = port;
        }

        unsafe { uninit.assume_init() }
    }
}

#[repr(C)]
struct pf_anchor_global {
    rbe_left: *mut pf_anchor,
    rbe_right: *mut pf_anchor,
    rbe_parent: *mut pf_anchor,
}

#[repr(C)]
struct pf_anchor_node {
    rbe_left: *mut pf_anchor,
    rbe_right: *mut pf_anchor,
    rbe_parent: *mut pf_anchor,
}

#[repr(C)]
struct pf_rulequeue {
    tqh_first: *mut Rule,
    tqh_last: *mut *mut Rule,
}

#[repr(C)]
struct pf_ruleset_rule {
    ptr: *mut pf_rulequeue,
    ptr_array: *mut *mut Rule,
    rcount: c_uint,
    rsize: c_uint,
    ticket: c_uint,
    open: c_int,
}

#[repr(C)]
struct pf_ruleset_rules {
    queues: [pf_rulequeue; 2],
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
    entry_global: pf_anchor_global,
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

    entries: pf_rule_list,
    rpool: Pool,

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
    #[cfg(target_os = "freebsd")]
    timeout: [c_uint; 20],
    #[cfg(target_os = "macos")]
    timeout: [c_uint; 26],
    #[cfg(target_os = "macos")]
    states: c_uint,
    max_states: c_uint,
    #[cfg(target_os = "macos")]
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
    af: AddressFamily, // sa_family_t
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
        let self_ptr = uninit.as_mut_ptr();

        unsafe {
            if let Some(from) = pf_rule.from {
                (*self_ptr).src = RuleAddr::new(from, pf_rule.from_port);
            }
            if let Some(to) = pf_rule.to {
                (*self_ptr).dst = RuleAddr::new(to, pf_rule.to_port);
            }
            if let Some(interface) = &pf_rule.interface {
                let len = interface.len().min(IFNAMSIZ - 1);
                (*self_ptr).ifname[..len].copy_from_slice(&interface.as_bytes()[..len]);
            }
            if let Some(label) = &pf_rule.label {
                let len = label.len().min(PF_RULE_LABEL_SIZE - 1);
                (*self_ptr).label[..len].copy_from_slice(&label.as_bytes()[..len]);
            }

            // Don't use routing tables.
            (*self_ptr).rtableid = -1;

            (*self_ptr).action = pf_rule.action;
            (*self_ptr).direction = pf_rule.direction;
            (*self_ptr).log = pf_rule.log;
            (*self_ptr).quick = pf_rule.quick;

            (*self_ptr).keep_state = pf_rule.keep_state;
            (*self_ptr).af = pf_rule.address_family();
            (*self_ptr).proto = pf_rule.proto as u8;
            (*self_ptr).flags = pf_rule.tcp_flags;
            (*self_ptr).flagset = pf_rule.tcp_flags_set;

            uninit.assume_init()
        }
    }
}

/// Equivalent to PF_CHANGE_... enum.
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
    pub(super) fn new(anchor: &str) -> Self {
        let mut uninit = MaybeUninit::<Self>::zeroed();
        let self_ptr = uninit.as_mut_ptr();

        // Copy anchor name.
        let len = anchor.len().min(MAXPATHLEN - 1);
        unsafe {
            (*self_ptr).anchor[..len].copy_from_slice(&anchor.as_bytes()[..len]);
        }

        unsafe { uninit.assume_init() }
    }

    #[must_use]
    pub(super) fn with_rule(anchor: &str, rule: Rule) -> Self {
        let mut uninit = MaybeUninit::<Self>::zeroed();
        let self_ptr = uninit.as_mut_ptr();

        // Copy anchor name.
        let len = anchor.len().min(MAXPATHLEN - 1);
        unsafe {
            (*self_ptr).anchor[..len].copy_from_slice(&anchor.as_bytes()[..len]);
            (*self_ptr).rule = rule;
        }

        unsafe { uninit.assume_init() }
    }
}

/// Equivalent to `struct pfioc_pooladdr`.
#[repr(C)]
pub(super) struct IocPoolAddr {
    action: Change,
    pub ticket: c_uint,
    nr: c_uint,
    r_num: c_uint,
    r_action: c_uchar,
    r_last: c_uchar,
    af: c_uchar,
    anchor: [c_uchar; MAXPATHLEN],
    pub addr: PoolAddr,
}

impl IocPoolAddr {
    #[must_use]
    pub fn new(anchor: &str) -> Self {
        let mut uninit = MaybeUninit::<Self>::zeroed();
        let self_ptr = uninit.as_mut_ptr();

        // Copy anchor name.
        let len = anchor.len().min(MAXPATHLEN - 1);
        unsafe {
            (*self_ptr).anchor[..len].copy_from_slice(&anchor.as_bytes()[..len]);
        }

        unsafe { uninit.assume_init() }
    }
}

/// Equivalent to `struct pfioc_trans_pfioc_trans_e`.
#[repr(C)]
pub(super) struct IocTransElement {
    rs_num: RuleSet,
    anchor: [c_uchar; MAXPATHLEN],
    pub ticket: c_uint,
}

impl IocTransElement {
    #[must_use]
    pub(super) fn new(ruleset: RuleSet, anchor: &str) -> Self {
        let mut uninit = MaybeUninit::<Self>::zeroed();
        let self_ptr = uninit.as_mut_ptr();

        // Set `RuleSet` and copy anchor name.
        let len = anchor.len().min(MAXPATHLEN - 1);
        unsafe {
            (*self_ptr).rs_num = ruleset;
            (*self_ptr).anchor[..len].copy_from_slice(&anchor.as_bytes()[..len]);
        }

        unsafe { uninit.assume_init() }
    }
}

/// Equivalent to `struct pfioc_trans`.
#[repr(C)]
pub(super) struct IocTrans {
    /// number of elements
    size: c_int,
    /// size of each element in bytes
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
// Stop the	packet filter.
ioctl_none!(pf_stop, b'D', 2);

// DIOCADDRULE
// Add rule at the end of the inactive ruleset. This call requires a ticket obtained through
// a preceding DIOCXBEGIN call and a pool_ticket obtained through a DIOCBEGINADDRS call.
// DIOCADDADDR must	also be	called if any pool addresses are required. The optional anchor name
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
// #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "netbsd"))]
ioctl_readwrite!(pf_begin_addrs, b'D', 51, IocPoolAddr);

// DIOCADDADDR
// #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "netbsd"))]
ioctl_readwrite!(pf_add_addr, b'D', 52, IocPoolAddr);

// DIOCGETRULESETS
// #[cfg(any(target_os = "freebsd", target_os = "openbsd"))]
// ioctl_readwrite!(pf_get_rulesets, b'D', 58, PFRuleset);

// DIOCGETRULESET
// #[cfg(any(target_os = "freebsd", target_os = "openbsd"))]
// ioctl_readwrite!(pf_get_ruleset, b'D', 59, PFRuleset);

// DIOCXBEGIN
ioctl_readwrite!(pf_begin, b'D', 81, IocTrans);

// DIOCXCOMMIT
ioctl_readwrite!(pf_commit, b'D', 82, IocTrans);

// DIOCXROLLBACK
ioctl_readwrite!(pf_rollback, b'D', 83, IocTrans);

// DIOCXEND
// Required by OpenBSD to release the ticket obtained by the DIOCGETRULES command.
// #[cfg(target_os = "openbsd")]
// ioctl_readwrite!(pf_end_trans, b'D', 100, c_int);

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

        assert_eq!(align_of::<IocRule>(), 8);
        #[cfg(target_os = "freebsd")]
        assert_eq!(size_of::<IocRule>(), 3040);
        #[cfg(target_os = "macos")]
        assert_eq!(size_of::<IocRule>(), 3104);
    }

    #[test]
    fn check_addr_wrap() {
        let ipnetv4 = IpNetwork::V4(Ipv4Network::new(Ipv4Addr::LOCALHOST, 8).unwrap());

        let addr_wrap = AddrWrap::new(ipnetv4);
        assert_eq!(
            addr_wrap.v.addr,
            [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            addr_wrap.v.mask,
            [255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );

        let ipv6 = IpNetwork::V6(Ipv6Network::new(Ipv6Addr::LOCALHOST, 32).unwrap());
        let addr_wrap = AddrWrap::new(ipv6);
        assert_eq!(
            addr_wrap.v.addr,
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );
        assert_eq!(
            addr_wrap.v.mask,
            [255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }
}
