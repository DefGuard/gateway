#[cfg(test)]
use std::str::FromStr;
use std::{
    ffi::CString,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use ipnetwork::IpNetwork;
#[cfg(test)]
use ipnetwork::{Ipv4Network, Ipv6Network};
use mnl::mnl_sys::libc;
use nftnl::{
    expr::{Expression, InterfaceName},
    nft_expr, nftnl_sys,
    set::{Set, SetKey},
    Batch, Chain, FinalizedBatch, ProtoFamily, Rule, Table,
};

use super::{proto, Action, Address, FilterRule, Port, Protocol, State};

const FILTER_TABLE: &str = "filter";
const NAT_TABLE: &str = "nat";
const DEFGUARD_TABLE: &str = "DEFGUARD";
const POSTROUTING_CHAIN: &str = "POSTROUTING";
const FORWARD_CHAIN: &str = "FORWARD";

#[derive(Debug, Clone)]
pub enum AddressMatch {
    IpList(Vec<IpAddr>),
    IpRange(IpAddr, IpAddr),
    Network(IpNetwork),
}

impl AddressMatch {
    pub fn is_empty(&self) -> bool {
        match self {
            Self::IpList(list) => list.is_empty(),
            _ => false,
        }
    }
}

impl Default for AddressMatch {
    fn default() -> Self {
        Self::IpList(Vec::new())
    }
}

impl From<Address> for AddressMatch {
    fn from(address: Address) -> Self {
        match address {
            Address::Ip(ip) => Self::IpList(vec![ip]),
            Address::Network(network) => Self::Network(network),
            Address::Range(start, end) => Self::IpRange(start, end),
        }
    }
}

struct InetService(u16);

impl SetKey for InetService {
    const TYPE: u32 = 13;
    const LEN: u32 = 2;

    fn data(&self) -> Box<[u8]> {
        Box::new(self.0.to_be_bytes())
    }
}

impl State {
    const fn to_expr_state(&self) -> nftnl::expr::ct::States {
        match self {
            Self::Established => nftnl::expr::ct::States::ESTABLISHED,
            Self::Invalid => nftnl::expr::ct::States::INVALID,
            Self::New => nftnl::expr::ct::States::NEW,
            Self::Related => nftnl::expr::ct::States::RELATED,
        }
    }
}

impl From<proto::enterprise::Protocol> for Protocol {
    fn from(proto: proto::enterprise::Protocol) -> Self {
        match proto {
            proto::enterprise::Protocol::Tcp => Self(libc::IPPROTO_TCP as u8),
            proto::enterprise::Protocol::Udp => Self(libc::IPPROTO_UDP as u8),
            proto::enterprise::Protocol::Icmp => Self(libc::IPPROTO_ICMP as u8),
            _ => {
                println!("Unsupported protocol: {:?}", proto);
                panic!();
            }
        }
    }
}

impl Protocol {
    pub fn supports_ports(&self) -> bool {
        matches!(self.0 as i32, libc::IPPROTO_TCP | libc::IPPROTO_UDP)
    }

    pub fn to_payload_expr(&self) -> &impl Expression {
        match self.0 as i32 {
            libc::IPPROTO_TCP => &nft_expr!(payload tcp dport),
            libc::IPPROTO_UDP => &nft_expr!(payload udp dport),
            _ => panic!("Unsupported protocol"),
        }
    }
}

impl SetKey for Protocol {
    const TYPE: u32 = 12;
    const LEN: u32 = 1;

    fn data(&self) -> Box<[u8]> {
        Box::new([self.0])
    }
}

pub trait FirewallRule {
    fn to_chain_rule<'a>(&self, chain: &'a Chain, batch: &mut Batch) -> Rule<'a>;
}

fn add_address_to_set(set: *mut nftnl_sys::nftnl_set, ip: &Address) {
    match ip {
        Address::Ip(ip) => match ip {
            IpAddr::V4(ip) => {
                add_to_set(set, ip, Some(ip));
            }
            IpAddr::V6(ip) => {
                add_to_set(set, ip, Some(ip));
            }
        },
        Address::Range(start, end) => match (start, end) {
            (IpAddr::V4(start), IpAddr::V4(end)) => {
                add_to_set(set, start, Some(end));
            }
            (IpAddr::V6(start), IpAddr::V6(end)) => {
                add_to_set(set, start, Some(end));
            }
            _ => panic!("Expected both addresses to be of the same type"),
        },
        Address::Network(network) => {
            let upper_bound = max_address(network);
            let net = network.network();
            match (net, upper_bound) {
                (IpAddr::V4(network), IpAddr::V4(upper_bound)) => {
                    add_to_set(set, &network, Some(&upper_bound));
                }
                (IpAddr::V6(network), IpAddr::V6(upper_bound)) => {
                    add_to_set(set, &network, Some(&upper_bound));
                }
                _ => panic!("Expected both addresses to be of the same type"),
            }
        }
    }
}

fn add_port_to_set(set: *mut nftnl_sys::nftnl_set, port: &Port) {
    match port {
        Port::Single(port) => {
            let inet_service = InetService(*port);
            add_to_set(set, &inet_service, Some(&inet_service));
        }
        Port::Range(start, end) => {
            let start = InetService(*start);
            let end = InetService(*end);

            add_to_set(set, &start, Some(&end));
        }
    }
}

fn add_protocol_to_set(set: *mut nftnl_sys::nftnl_set, proto: &Protocol) {
    add_to_set(set, proto, Some(proto));
}

impl FirewallRule for FilterRule {
    fn to_chain_rule<'a>(&self, chain: &'a Chain, batch: &mut Batch) -> Rule<'a> {
        let mut rule = Rule::new(chain);

        // let tcp = self.protocol == Some(libc::IPPROTO_TCP as u8);
        // let tcp = matches!(self.protocol, Some(proto) if proto.0 == libc::IPPROTO_TCP as u8);
        // println!("TCP: {}", tcp);
        let v4 = true;

        if !self.dest_ports.is_empty() && self.protocols.len() > 1 {
            panic!("Cannot specify multiple protocols with destination ports");
        }

        let mut id_counter = self.id;

        // TODO: Reduce code duplication here
        if !self.src_ips.is_empty() {
            if v4 {
                let set = new_anon_set::<Ipv4Addr>(
                    id_counter,
                    chain.get_table(),
                    ProtoFamily::Inet,
                    true,
                );
                id_counter += 1;
                batch.add(&set, nftnl::MsgType::Add);

                for ip in &self.src_ips {
                    add_address_to_set(set.as_ptr(), ip);
                }

                set.elems_iter().for_each(|elem| {
                    batch.add(&elem, nftnl::MsgType::Add);
                });

                rule.add_expr(&nft_expr!(meta nfproto));
                rule.add_expr(&nft_expr!(cmp == libc::NFPROTO_IPV4 as u8));
                rule.add_expr(&nft_expr!(payload ipv4 saddr));

                rule.add_expr(&nft_expr!(lookup & set));
            } else {
                let set = new_anon_set::<Ipv6Addr>(
                    id_counter,
                    chain.get_table(),
                    ProtoFamily::Inet,
                    true,
                );
                id_counter += 1;

                batch.add(&set, nftnl::MsgType::Add);

                for ip in &self.src_ips {
                    add_address_to_set(set.as_ptr(), ip);
                }

                set.elems_iter().for_each(|elem| {
                    batch.add(&elem, nftnl::MsgType::Add);
                });

                rule.add_expr(&nft_expr!(meta nfproto));
                rule.add_expr(&nft_expr!(cmp == libc::NFPROTO_IPV6 as u8));
                rule.add_expr(&nft_expr!(payload ipv6 saddr));

                rule.add_expr(&nft_expr!(lookup & set));
            }
        }

        // TODO: Reduce code duplication here
        if !self.dest_ips.is_empty() {
            if v4 {
                let set = new_anon_set::<Ipv4Addr>(
                    id_counter,
                    chain.get_table(),
                    ProtoFamily::Inet,
                    true,
                );
                id_counter += 1;
                batch.add(&set, nftnl::MsgType::Add);

                for ip in &self.dest_ips {
                    add_address_to_set(set.as_ptr(), ip);
                }

                set.elems_iter().for_each(|elem| {
                    batch.add(&elem, nftnl::MsgType::Add);
                });

                rule.add_expr(&nft_expr!(meta nfproto));
                rule.add_expr(&nft_expr!(cmp == libc::NFPROTO_IPV4 as u8));
                rule.add_expr(&nft_expr!(payload ipv4 daddr));

                rule.add_expr(&nft_expr!(lookup & set));
            } else {
                let set = new_anon_set::<Ipv6Addr>(
                    id_counter,
                    chain.get_table(),
                    ProtoFamily::Inet,
                    true,
                );
                id_counter += 1;
                batch.add(&set, nftnl::MsgType::Add);

                for ip in &self.dest_ips {
                    add_address_to_set(set.as_ptr(), ip);
                }

                set.elems_iter().for_each(|elem| {
                    batch.add(&elem, nftnl::MsgType::Add);
                });

                rule.add_expr(&nft_expr!(meta nfproto));
                rule.add_expr(&nft_expr!(cmp == libc::NFPROTO_IPV6 as u8));
                rule.add_expr(&nft_expr!(payload ipv6 daddr));

                rule.add_expr(&nft_expr!(lookup & set));
            }
        }

        if !self.protocols.is_empty() {
            // If there are many protocols, put them as a set
            if self.protocols.len() > 1 {
                let set = new_anon_set::<Protocol>(
                    id_counter,
                    chain.get_table(),
                    ProtoFamily::Inet,
                    true,
                );
                id_counter += 1;
                batch.add(&set, nftnl::MsgType::Add);

                for proto in &self.protocols {
                    add_protocol_to_set(set.as_ptr(), proto);
                }

                set.elems_iter().for_each(|elem| {
                    batch.add(&elem, nftnl::MsgType::Add);
                });

                rule.add_expr(&nft_expr!(meta l4proto));
                rule.add_expr(&nft_expr!(lookup & set));
            } else if !self.dest_ports.is_empty() {
                let protocol = self.protocols.first().unwrap();
                println!("Protocol: {:?}", protocol);
                if protocol.supports_ports() {
                    let set = new_anon_set::<InetService>(
                        id_counter,
                        chain.get_table(),
                        ProtoFamily::Inet,
                        true,
                    );
                    id_counter += 1;
                    batch.add(&set, nftnl::MsgType::Add);

                    for port in &self.dest_ports {
                        add_port_to_set(set.as_ptr(), port);
                    }

                    set.elems_iter().for_each(|elem| {
                        batch.add(&elem, nftnl::MsgType::Add);
                    });

                    rule.add_expr(&nft_expr!(meta l4proto));
                    rule.add_expr(&nft_expr!(cmp == protocol.0));
                    rule.add_expr(protocol.to_payload_expr());
                    rule.add_expr(&nft_expr!(lookup & set));
                    // rule.add_expr(&nft_expr!(meta l4proto));
                    // if tcp {
                    //     rule.add_expr(&nft_expr!(cmp == libc::IPPROTO_TCP as u8));
                    //     rule.add_expr(&nft_expr!(payload tcp dport));
                    // } else {
                    //     rule.add_expr(&nft_expr!(cmp == libc::IPPROTO_UDP as u8));
                    //     rule.add_expr(&nft_expr!(payload udp dport));
                    // }
                }
            }
        }

        if let Some(iifname) = &self.iifname {
            rule.add_expr(&nft_expr!(meta iifname));
            let exact = InterfaceName::Exact(CString::new(iifname.as_str()).unwrap());
            rule.add_expr(&nft_expr!(cmp == exact));
        }

        if let Some(oifname) = &self.oifname {
            rule.add_expr(&nft_expr!(meta oifname));
            let exact = InterfaceName::Exact(CString::new(oifname.as_str()).unwrap());
            rule.add_expr(&nft_expr!(cmp == exact));
        }

        if !self.states.is_empty() {
            let combined_states = self
                .states
                .iter()
                .fold(0u32, |acc, state| acc | state.to_expr_state().bits());
            rule.add_expr(&nft_expr!(ct state));
            rule.add_expr(&nft_expr!(bitwise mask combined_states, xor 0u32));
            rule.add_expr(&nft_expr!(cmp != 0u32));
        }

        if self.counter {
            rule.add_expr(&nft_expr!(counter));
        }

        match self.action {
            Action::Accept => {
                rule.add_expr(&nft_expr!(verdict accept));
            }
            Action::Drop => {
                rule.add_expr(&nft_expr!(verdict drop));
            }
            Action::None => {}
        }

        rule
    }
}

#[derive(Debug, Default)]
struct NatRule {
    src_ip: Option<IpAddr>,
    dest_ip: Option<IpAddr>,
    oifname: Option<String>,
    iifname: Option<String>,
    counter: bool,
}

impl FirewallRule for NatRule {
    fn to_chain_rule<'a>(&self, chain: &'a Chain, _batch: &mut Batch) -> Rule<'a> {
        let mut rule = Rule::new(chain);

        if let Some(src_ip) = self.src_ip {
            if src_ip.is_ipv4() {
                rule.add_expr(&nft_expr!(payload ipv4 saddr));
            } else {
                rule.add_expr(&nft_expr!(payload ipv6 saddr));
            }
            rule.add_expr(&nft_expr!(cmp == src_ip));
        }

        if let Some(dest_ip) = self.dest_ip {
            if dest_ip.is_ipv4() {
                rule.add_expr(&nft_expr!(payload ipv4 daddr));
            } else {
                rule.add_expr(&nft_expr!(payload ipv6 daddr));
            }
            rule.add_expr(&nft_expr!(cmp == dest_ip));
        }

        if let Some(iifname) = &self.iifname {
            rule.add_expr(&nft_expr!(meta iifname));
            let exact = InterfaceName::Exact(CString::new(iifname.as_str()).unwrap());
            rule.add_expr(&nft_expr!(cmp == exact));
        }

        if let Some(oifname) = &self.oifname {
            rule.add_expr(&nft_expr!(meta oifname));
            let exact = InterfaceName::Exact(CString::new(oifname.as_str()).unwrap());
            rule.add_expr(&nft_expr!(cmp == exact));
        }

        if self.counter {
            rule.add_expr(&nft_expr!(counter));
        }

        rule.add_expr(&nft_expr!(masquerade));

        rule
    }
}

struct JumpRule;

impl JumpRule {
    fn to_chain_rule<'a>(src_chain: &'a Chain, dest_chain: &'a Chain) -> Rule<'a> {
        let mut rule = Rule::new(src_chain);

        rule.add_expr(&nft_expr!(counter));
        rule.add_expr(&nft_expr!(verdict jump dest_chain.get_name().into()));

        rule
    }
}

/// Sets up the default chains for the firewall
pub fn init_firewall() -> io::Result<()> {
    let mut batch = Batch::new();
    let table = Tables::Defguard(ProtoFamily::Inet).to_table();

    batch.add(&table, nftnl::MsgType::Add);
    batch.add(&table, nftnl::MsgType::Del);
    batch.add(&table, nftnl::MsgType::Add);

    let mut chain = Chains::Forward.to_chain(&table);
    chain.set_hook(nftnl::Hook::Forward, 0);
    // FIXME: This should be configurable
    chain.set_policy(nftnl::Policy::Accept);
    chain.set_type(nftnl::ChainType::Filter);
    batch.add(&chain, nftnl::MsgType::Add);

    let mut nat_chain = Chains::Postrouting.to_chain(&table);
    nat_chain.set_hook(nftnl::Hook::PostRouting, 100);
    nat_chain.set_policy(nftnl::Policy::Accept);
    nat_chain.set_type(nftnl::ChainType::Nat);
    batch.add(&nat_chain, nftnl::MsgType::Add);

    let finalized_batch = batch.finalize();

    send_batch(&finalized_batch);

    Ok(())
}

pub fn clear_chains() {
    let mut batch = Batch::new();
    let table = Tables::Defguard(ProtoFamily::Inet).to_table();
    batch.add(&table, nftnl::MsgType::Add);
    batch.add(&table, nftnl::MsgType::Del);

    let finalized_batch = batch.finalize();

    send_batch(&finalized_batch);
}

/// Applies masquerade on the specified interface for the outgoing packets
pub fn masq_interface(ifname: &str) -> io::Result<()> {
    let mut batch = Batch::new();
    let table = Tables::Defguard(ProtoFamily::Inet).to_table();
    batch.add(&table, nftnl::MsgType::Add);

    let post_routing = Chains::Postrouting.to_chain(&table);
    batch.add(&post_routing, nftnl::MsgType::Add);

    let nat_rule = NatRule {
        oifname: Some(ifname.to_string()),
        counter: true,
        ..Default::default()
    }
    .to_chain_rule(&post_routing, &mut batch);

    batch.add(&nat_rule, nftnl::MsgType::Add);

    let finalized_batch = batch.finalize();
    send_batch(&finalized_batch);

    Ok(())
}

pub enum Tables {
    Filter(ProtoFamily),
    Nat(ProtoFamily),
    Defguard(ProtoFamily),
}

impl Tables {
    fn to_table(&self) -> Table {
        match self {
            Self::Filter(family) => Table::new(&CString::new(FILTER_TABLE).unwrap(), *family),
            Self::Nat(family) => Table::new(&CString::new(NAT_TABLE).unwrap(), *family),
            Self::Defguard(family) => Table::new(&CString::new(DEFGUARD_TABLE).unwrap(), *family),
        }
    }
}

pub enum Chains {
    Forward,
    Postrouting,
}

impl Chains {
    fn to_chain<'a>(&self, table: &'a Table) -> Chain<'a> {
        match self {
            Self::Forward => Chain::new(&CString::new(FORWARD_CHAIN).unwrap(), table),
            Self::Postrouting => Chain::new(&CString::new(POSTROUTING_CHAIN).unwrap(), table),
        }
    }
}

pub fn apply_filter_rules(rules: Vec<FilterRule>) {
    let mut batch = Batch::new();
    let table = Tables::Defguard(ProtoFamily::Inet).to_table();
    batch.add(&table, nftnl::MsgType::Add);

    let forward_chain = Chains::Forward.to_chain(&table);
    batch.add(&forward_chain, nftnl::MsgType::Add);

    for rule in rules.iter() {
        let chain_rule = rule.to_chain_rule(&forward_chain, &mut batch);
        batch.add(&chain_rule, nftnl::MsgType::Add);
    }

    let finalized_batch = batch.finalize();

    send_batch(&finalized_batch);
}

fn send_batch(batch: &FinalizedBatch) {
    let socket = mnl::Socket::new(mnl::Bus::Netfilter).unwrap();
    socket.send_all(batch).unwrap();

    let portid = socket.portid();
    let mut buffer = vec![0; nftnl::nft_nlmsg_maxsize() as usize];

    // TODO: Why is it 2?
    let seq = 2;
    while let Some(message) = socket_recv(&socket, &mut buffer[..]) {
        match mnl::cb_run(message, seq, portid).unwrap() {
            mnl::CbResult::Stop => {
                println!("STOP");
                break;
            }
            mnl::CbResult::Ok => {
                println!("OK");
            }
        };
    }
}

fn socket_recv<'a>(socket: &mnl::Socket, buf: &'a mut [u8]) -> Option<&'a [u8]> {
    let ret = socket.recv(buf).unwrap();
    println!("Received {} bytes", ret);
    if ret > 0 {
        Some(&buf[..ret])
    } else {
        None
    }
}

/// Get the max address in a network.
///
/// - In IPv4 this is the broadcast address.
/// - In IPv6 this is just the last address in the network.
fn max_address(network: &IpNetwork) -> IpAddr {
    match network {
        IpNetwork::V4(network) => {
            let ip_u32 = u32::from(network.ip());
            let mask_u32 = u32::from(network.mask());

            IpAddr::V4(Ipv4Addr::from(ip_u32 | !mask_u32))
        }
        IpNetwork::V6(network) => {
            let ip_u128 = u128::from(network.ip());
            let mask_u128 = u128::from(network.mask());

            IpAddr::V6(Ipv6Addr::from(ip_u128 | !mask_u128))
        }
    }
}

fn new_anon_set<T>(id: u32, table: &Table, family: ProtoFamily, interval_set: bool) -> Set<T>
where
    T: SetKey,
{
    let set = Set::<T>::new(&CString::new("__set%d").unwrap(), id, table, family);

    if interval_set {
        unsafe {
            nftnl_sys::nftnl_set_set_u32(
                set.as_ptr(),
                nftnl_sys::NFTNL_SET_FLAGS as u16,
                (libc::NFT_SET_ANONYMOUS | libc::NFT_SET_CONSTANT | libc::NFT_SET_INTERVAL) as u32,
            );
        }
    }

    set
}

/// Adds key to a set. If the range_end option is specified, it will assume the lower and upper
/// bounds of a range need to be added.
fn add_to_set<K>(set: *mut nftnl_sys::nftnl_set, key: &K, range_end: Option<&K>)
where
    K: SetKey,
{
    let key_data = key.data();
    let key_data_len = key_data.len() as u32;

    unsafe {
        let elem = nftnl_sys::nftnl_set_elem_alloc();
        assert!(!elem.is_null(), "oom");
        nftnl_sys::nftnl_set_elem_set(
            elem,
            nftnl_sys::NFTNL_SET_ELEM_KEY as u16,
            key_data.as_ptr().cast(),
            key_data_len,
        );
        nftnl_sys::nftnl_set_elem_add(set, elem);

        if let Some(end) = range_end {
            let mut end_data = end.data();

            // This is a workaround to make the upper bound inclusive.
            // Perhaps there is a better way to do this.
            increment_bytes(&mut end_data);
            let end_data_len = (end_data.len()) as u32;

            let elem = nftnl_sys::nftnl_set_elem_alloc();
            assert!(!elem.is_null(), "oom");
            nftnl_sys::nftnl_set_elem_set(
                elem,
                nftnl_sys::NFTNL_SET_ELEM_KEY as u16,
                end_data.as_ptr().cast(),
                end_data_len,
            );
            nftnl_sys::nftnl_set_elem_set_u32(
                elem,
                nftnl_sys::NFTNL_SET_ELEM_FLAGS as u16,
                libc::NFT_SET_ELEM_INTERVAL_END as u32,
            );
            nftnl_sys::nftnl_set_elem_add(set, elem);
        }
    }
}

fn increment_bytes(bytes: &mut [u8]) {
    for i in (0..bytes.len()).rev() {
        if bytes[i] < 255 {
            bytes[i] += 1;
            return;
        } else {
            bytes[i] = 0;
        }
    }

    // the bytes have overflown, but that's okay for our purposes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_increment_ipv4_basic() {
        let mut ip = [192, 168, 1, 1];
        increment_bytes(&mut ip);
        assert_eq!(ip, [192, 168, 1, 2]);
    }

    #[test]
    fn test_increment_ipv4_overflow_last_octet() {
        let mut ip = [192, 168, 1, 255];
        increment_bytes(&mut ip);
        assert_eq!(ip, [192, 168, 2, 0]);
    }

    #[test]
    fn test_increment_ipv4_overflow_multiple_octets() {
        let mut ip = [192, 168, 255, 255];
        increment_bytes(&mut ip);
        assert_eq!(ip, [192, 169, 0, 0]);
    }

    #[test]
    fn test_increment_ipv4_max_address() {
        let mut ip = [255, 255, 255, 255];
        increment_bytes(&mut ip);
        assert_eq!(ip, [0, 0, 0, 0]);
    }

    #[test]
    fn test_increment_ipv4_zero_address() {
        let mut ip = [0, 0, 0, 0];
        increment_bytes(&mut ip);
        assert_eq!(ip, [0, 0, 0, 1]);
    }

    #[test]
    fn test_increment_ipv6_basic() {
        let mut ip = [0, 0, 0, 0, 0, 0, 0, 0];
        increment_bytes(&mut ip);
        assert_eq!(ip, [0, 0, 0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn test_increment_ipv6_overflow_last_octet() {
        let mut ip = [0, 0, 0, 0, 0, 0, 0, 255];
        increment_bytes(&mut ip);
        assert_eq!(ip, [0, 0, 0, 0, 0, 0, 1, 0]);
    }

    #[test]
    fn test_increment_ipv6_overflow_multiple_octets() {
        let mut ip = [0, 0, 0, 0, 0, 0, 255, 255];
        increment_bytes(&mut ip);
        assert_eq!(ip, [0, 0, 0, 0, 0, 1, 0, 0]);
    }

    #[test]
    fn test_increment_ipv6_max_address() {
        let mut ip = [255, 255, 255, 255, 255, 255, 255, 255];
        increment_bytes(&mut ip);
        assert_eq!(ip, [0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_max_address_ipv4_24() {
        let network = IpNetwork::V4(Ipv4Network::from_str("192.168.1.0/24").unwrap());
        let max = max_address(&network);
        assert_eq!(max, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 255)));
    }

    #[test]
    fn test_max_address_ipv4_16() {
        let network = IpNetwork::V4(Ipv4Network::from_str("10.1.0.0/16").unwrap());
        let max = max_address(&network);
        assert_eq!(max, IpAddr::V4(Ipv4Addr::new(10, 1, 255, 255)));
    }

    #[test]
    fn test_max_address_ipv4_8() {
        let network = IpNetwork::V4(Ipv4Network::from_str("172.16.0.0/8").unwrap());
        let max = max_address(&network);
        assert_eq!(max, IpAddr::V4(Ipv4Addr::new(172, 255, 255, 255)));
    }

    #[test]
    fn test_max_address_ipv4_32() {
        let network = IpNetwork::V4(Ipv4Network::from_str("192.168.1.1/32").unwrap());
        let max = max_address(&network);
        assert_eq!(max, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn test_max_address_ipv6_64() {
        let network = IpNetwork::V6(Ipv6Network::from_str("2001:db8::/64").unwrap());
        let max = max_address(&network);
        assert_eq!(
            max,
            IpAddr::V6(Ipv6Addr::from_str("2001:db8::ffff:ffff:ffff:ffff").unwrap())
        );
    }

    #[test]
    fn test_max_address_ipv6_128() {
        let network = IpNetwork::V6(Ipv6Network::from_str("2001:db8::1/128").unwrap());
        let max = max_address(&network);
        assert_eq!(max, IpAddr::V6(Ipv6Addr::from_str("2001:db8::1").unwrap()));
    }

    #[test]
    fn test_max_address_ipv6_48() {
        let network = IpNetwork::V6(Ipv6Network::from_str("2001:db8:1234::/48").unwrap());
        let max = max_address(&network);
        assert_eq!(
            max,
            IpAddr::V6(Ipv6Addr::from_str("2001:db8:1234:ffff:ffff:ffff:ffff:ffff").unwrap())
        );
    }
}
