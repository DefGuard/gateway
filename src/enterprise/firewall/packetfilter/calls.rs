use std::{
    ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_ulong, c_ushort, c_void},
    mem::{size_of, MaybeUninit},
};

use ipnetwork::IpNetwork;
use libc::{pid_t, sa_family_t, uid_t, IFNAMSIZ};
use nix::{ioctl_none, ioctl_readwrite};

use super::rule::{Action, AddressFamily, Direction, PacketFilterRule, RuleSet, State};
use crate::enterprise::firewall::Port;

/// Equivalent to `struct pf_addr`: fits 128-bit address, either IPv4 or IPv6.
type Addr = [u8; 16]; // Do not use u128 for the sake of alignment.
/// Equivalent to `pf_poolhashkey`: 128-bit hash key.
type PoolHashKey = [u8; 16];

const PF_TABLE_NAME_SIZE: usize = 32;
#[cfg(target_os = "macos")]
const RTLABEL_LEN: usize = 32;

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
pub struct AddrWrap {
    v: AddrMask,
    // pub v: pf_addr_wrap_v,
    // unused in this crate
    // pub p: pf_addr_wrap_p,
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
pub struct RuleAddr {
    pub addr: AddrWrap,
    // macOS: here `union pf_rule_xport` is flattened to its first variant: `struct pf_port_range`.
    pub port: [c_ushort; 2],
    pub op: PortOp,
    #[cfg(target_os = "macos")]
    _padding: [c_uchar; 3],
    #[cfg(target_os = "macos")]
    pub neg: c_uchar,
}

impl RuleAddr {
    #[must_use]
    pub fn new(ip_network: IpNetwork, port: Port) -> Self {
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
pub struct pf_rule_list {
    pub tqe_next: *mut Rule,
    pub tqe_prev: *mut *mut Rule,
}

#[repr(C)]
pub struct pf_pooladdr_list {
    pub tqe_next: *mut PoolAddr,
    pub tqe_prev: *mut *mut PoolAddr,
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

#[derive(Debug)]
#[repr(C)]
pub struct pf_palist {
    pub tqh_first: *mut PoolAddr,
    pub tqh_last: *mut *mut PoolAddr,
}

/// Equivalent to `struct pf_pool`.
#[derive(Debug)]
#[repr(C)]
pub struct Pool {
    pub list: pf_palist,
    pub cur: *mut c_void,
    pub key: PoolHashKey,
    pub counter: Addr,
    pub tblidx: c_int,
    pub proxy_port: [c_ushort; 2],
    #[cfg(target_os = "macos")]
    pub port_op: PortOp,
    pub opts: c_uchar,
    #[cfg(target_os = "macos")]
    pub af: sa_family_t,
}

#[derive(Debug)]
#[repr(u8)]
pub enum PortOp {
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
pub struct pf_anchor_global {
    pub rbe_left: *mut pf_anchor,
    pub rbe_right: *mut pf_anchor,
    pub rbe_parent: *mut pf_anchor,
}

#[repr(C)]
pub struct pf_anchor_node {
    pub rbe_left: *mut pf_anchor,
    pub rbe_right: *mut pf_anchor,
    pub rbe_parent: *mut pf_anchor,
}

#[repr(C)]
pub struct pf_rulequeue {
    pub tqh_first: *mut Rule,
    pub tqh_last: *mut *mut Rule,
}

#[repr(C)]
pub struct pf_ruleset_rule {
    pub ptr: *mut pf_rulequeue,
    pub ptr_array: *mut *mut Rule,
    pub rcount: c_uint,
    pub rsize: c_uint,
    pub ticket: c_uint,
    pub open: c_int,
}

#[repr(C)]
pub struct pf_ruleset_rules {
    pub queues: [pf_rulequeue; 2],
    pub active: pf_ruleset_rule,
    pub inactive: pf_ruleset_rule,
}

#[repr(C)]
pub struct pf_ruleset {
    pub rules: [pf_ruleset_rules; 6],
    pub anchor: *mut pf_anchor,
    pub tticket: c_uint,
    pub tables: c_int,
    pub topen: c_int,
}

#[repr(C)]
pub struct pf_anchor {
    pub entry_global: pf_anchor_global,
    pub entry_node: pf_anchor_node,
    pub parent: *mut pf_anchor,
    pub children: pf_anchor_node,
    pub name: [c_char; 64],
    pub path: [c_char; 1024],
    pub ruleset: pf_ruleset,
    pub refcnt: c_int,
    pub match_: c_int,
    pub owner: [c_char; 64],
}

/// A packed Operating System description for fingerprinting.
type pf_osfp_t = c_uint;
// #define PF_OSFP_ANY	((pf_osfp_t)0)
// #define PF_OSFP_UNKNOWN	((pf_osfp_t)-1)
// #define PF_OSFP_NOMATCH	((pf_osfp_t)-2)

#[derive(Debug)]
#[repr(C)]
pub struct pf_rule_conn_rate {
    pub limit: c_uint,
    pub seconds: c_uint,
}

#[derive(Debug)]
#[repr(C)]
pub struct pf_rule_id {
    pub uid: [uid_t; 2],
    pub op: c_uchar,
    // pub _pad: [u_int8_t; 3],
}

/// As defined in `net/pfvar.h`.
const PF_RULE_LABEL_SIZE: usize = 64;

/// Equivalent to 'struct pf_rule'.
#[derive(Debug)]
#[repr(C)]
pub struct Rule {
    src: RuleAddr,
    pub dst: RuleAddr,

    pub skip: [usize; 8],
    pub label: [c_uchar; PF_RULE_LABEL_SIZE],
    pub ifname: [c_uchar; IFNAMSIZ],
    pub qname: [c_uchar; 64],
    pub pqname: [c_uchar; 64],
    pub tagname: [c_uchar; 64],
    pub match_tagname: [c_uchar; 64],
    pub overload_tblname: [c_uchar; 32],

    pub entries: pf_rule_list,
    pub rpool: Pool,

    pub evaluations: c_long,
    pub packets: [c_ulong; 2],
    pub bytes: [c_ulong; 2],

    #[cfg(target_os = "macos")]
    pub ticket: c_ulong,
    #[cfg(target_os = "macos")]
    pub owner: [c_char; 64],
    #[cfg(target_os = "macos")]
    pub priority: c_int,

    pub kif: *mut c_void, // struct pfi_kif, kernel only
    pub anchor: *mut pf_anchor,
    pub overload_tbl: *mut c_void, // struct pfr_ktable, kernel only

    pub os_fingerprint: pf_osfp_t,

    pub rtableid: c_uint,
    #[cfg(target_os = "freebsd")]
    pub timeout: [c_uint; 20],
    #[cfg(target_os = "macos")]
    pub timeout: [c_uint; 26],
    #[cfg(target_os = "macos")]
    pub states: c_uint,
    pub max_states: c_uint,
    #[cfg(target_os = "macos")]
    pub src_nodes: c_uint,
    pub max_src_nodes: c_uint,
    pub max_src_states: c_uint,
    pub max_src_conn: c_uint,
    pub max_src_conn_rate: pf_rule_conn_rate,
    pub qid: c_uint,
    pub pqid: c_uint,
    pub rt_listid: c_uint,
    pub nr: c_uint,
    pub prob: c_uint,
    pub cuid: uid_t,
    pub cpid: pid_t,

    #[cfg(target_os = "freebsd")]
    pub states_cur: u64,
    #[cfg(target_os = "freebsd")]
    pub states_tot: u64,
    #[cfg(target_os = "freebsd")]
    pub src_nodes: u64,

    pub return_icmp: c_ushort,
    pub return_icmp6: c_ushort,
    pub max_mss: c_ushort,
    pub tag: c_ushort,
    pub match_tag: c_ushort,
    #[cfg(target_os = "freebsd")]
    pub scrub_flags: c_ushort,

    pub uid: pf_rule_id,
    pub gid: pf_rule_id,

    pub rule_flag: c_uint, // RuleFlag
    pub action: Action,
    pub direction: Direction,
    pub log: c_uchar, // LogFlags
    pub logif: c_uchar,
    pub quick: bool,
    pub ifnot: c_uchar,
    pub match_tag_not: c_uchar,
    pub natpass: c_uchar,

    pub keep_state: State,
    pub af: AddressFamily, // sa_family_t
    pub proto: c_uchar,
    pub(crate) r#type: c_uchar,
    pub code: c_uchar,
    pub flags: c_uchar,   // TCP_FLAG
    pub flagset: c_uchar, // TCP_FLAG
    pub min_ttl: c_uchar,
    pub allow_opts: c_uchar,
    pub rt: c_uchar,
    pub return_ttl: c_uchar,

    pub tos: c_uchar,
    #[cfg(target_os = "freebsd")]
    pub set_tos: c_uchar,
    pub anchor_relative: c_uchar,
    pub anchor_wildcard: c_uchar,
    pub flush: c_uchar,
    #[cfg(target_os = "freebsd")]
    pub prio: c_uchar,
    #[cfg(target_os = "freebsd")]
    pub set_prio: [c_uchar; 2],

    #[cfg(target_os = "freebsd")]
    pub divert: (pf_addr, u16),

    #[cfg(target_os = "freebsd")]
    pub u_states_cur: u64,
    #[cfg(target_os = "freebsd")]
    pub u_states_tot: u64,
    #[cfg(target_os = "freebsd")]
    pub u_src_nodes: u64,

    #[cfg(target_os = "macos")]
    pub proto_variant: c_uchar,
    #[cfg(target_os = "macos")]
    pub extfilter: c_uchar,
    #[cfg(target_os = "macos")]
    pub extmap: c_uchar,
    #[cfg(target_os = "macos")]
    pub dnpipe: c_uint,
    #[cfg(target_os = "macos")]
    pub dntype: c_uint,
}

impl Rule {
    // TODO: expand
    #[must_use]
    pub fn new(src: IpNetwork, src_port: Port) -> Self {
        let mut uninit = MaybeUninit::<Self>::zeroed();
        let self_ptr = uninit.as_mut_ptr();

        unsafe {
            (*self_ptr).dst = RuleAddr::new(src, src_port);
            // Set address family.
            // TODO: match empty network, then set AF_UNSPEC.
            // (*self_ptr).af = match src {
            //     IpNetwork::V4(_) => AF_INET as u8,
            //     IpNetwork::V6(_) => AF_INET6 as u8,
            // };
            (*self_ptr).keep_state = State::Normal;

            uninit.assume_init()
        }
    }

    pub fn from_rule(pf_rule: &PacketFilterRule) -> Self {
        let mut uninit = MaybeUninit::<Self>::zeroed();
        let self_ptr = uninit.as_mut_ptr();

        unsafe {
            if let Some(from) = pf_rule.from {
                (*self_ptr).src = RuleAddr::new(from, pf_rule.from_port);
            }
            if let Some(to) = pf_rule.to {
                (*self_ptr).dst = RuleAddr::new(to, pf_rule.to_port);
            }
            if let Some(label) = &pf_rule.label {
                let len = label.len().min(PF_RULE_LABEL_SIZE - 1);
                (*self_ptr).label[..len].copy_from_slice(&label.as_bytes()[..len]);
            }
            (*self_ptr).action = pf_rule.action;
            (*self_ptr).direction = pf_rule.direction;
            (*self_ptr).quick = pf_rule.quick;
            (*self_ptr).af = pf_rule.address_family();

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

// 1024 bytes
pub(crate) const MAXPATHLEN: usize = libc::PATH_MAX as usize;

/// Equivalent to `struct pfioc_rule`.
#[repr(C)]
pub struct IocRule {
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

    #[must_use]
    pub fn with_rule(anchor: &str, rule: Rule) -> Self {
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
pub struct IocPoolAddr {
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

    // pub fn set_addr(&mut self, addr:) {

    // }
}

/// Equivalent to `struct pfioc_trans_pfioc_trans_e`.
#[repr(C)]
pub struct IocTransElement {
    rs_num: RuleSet,
    anchor: [c_uchar; MAXPATHLEN],
    pub ticket: c_uint,
}

impl IocTransElement {
    #[must_use]
    pub fn new(ruleset: RuleSet, anchor: &str) -> Self {
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
pub struct IocTrans {
    /// number of elements
    size: c_int,
    /// size of each element in bytes
    esize: c_int,
    array: *mut IocTransElement,
}

impl IocTrans {
    #[must_use]
    pub fn new(elements: &mut [IocTransElement]) -> Self {
        Self {
            size: elements.len() as i32,
            esize: size_of::<IocTransElement>() as i32,
            array: elements.as_mut_ptr(),
        }
    }
}

// fn setup_trans(
//     pfioc_trans: &mut pfioc_trans,
//     pfioc_trans_elements: &mut [ffi::pfvar::pfioc_trans_pfioc_trans_e],
// ) {
//     pfioc_trans.size = pfioc_trans_elements.len() as i32;
//     pfioc_trans.esize = size_of::<ffi::pfvar::pfioc_trans_pfioc_trans_e>() as i32;
//     pfioc_trans.array = pfioc_trans_elements.as_mut_ptr();
// }

// DIOCSTART
ioctl_none!(pf_start, b'D', 1);

// DIOCSTOP
ioctl_none!(pf_stop, b'D', 2);

// DIOCADDRULE
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
        assert_eq!(size_of::<IocRule>(), 3104);
        #[cfg(target_os = "macos")]
        assert_eq!(size_of::<IocRule>(), 3104);
    }

    #[test]
    fn check_pf_addr_wrap() {
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
