#[cfg(test)]
use std::str::FromStr;
use std::{
    ffi::{CStr, CString},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use ipnetwork::IpNetwork;
#[cfg(test)]
use ipnetwork::{Ipv4Network, Ipv6Network};
use nftnl::{
    expr::{Expression, Immediate, InterfaceName, Nat, NatType, Register},
    nft_expr, nftnl_sys,
    set::{Set, SetKey},
    Batch, Chain, FinalizedBatch, ProtoFamily, Rule, Table,
};

use super::{get_set_id, Address, FilterRule, Policy, Port, Protocol, State};
use crate::enterprise::firewall::{iprange::IpAddrRange, FirewallError, SnatBinding};

const FILTER_TABLE: &str = "filter";
const NAT_TABLE: &str = "nat";
const DEFGUARD_TABLE: &str = "DEFGUARD-";
const POSTROUTING_CHAIN: &str = "POSTROUTING";
const FORWARD_CHAIN: &str = "FORWARD";
const ANON_SET_NAME: &CStr = c"__set%d";
const LOOPBACK_IFACE: &str = "lo";

const POSTROUTING_PRIORITY: i32 = 100;
const FORWARD_PRIORITY: i32 = 0;

struct InetService(u16);

impl SetKey for InetService {
    const LEN: u32 = 2;
    const TYPE: u32 = 13;

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

impl Protocol {
    pub(crate) fn as_port_payload_expr(&self) -> Result<&impl Expression, FirewallError> {
        match self {
            Self::Tcp => Ok(&nft_expr!(payload tcp dport)),
            Self::Udp => Ok(&nft_expr!(payload udp dport)),
            _ => Err(FirewallError::UnsupportedProtocol(*self as u8)),
        }
    }
}

impl From<Policy> for nftnl::Policy {
    fn from(policy: Policy) -> Self {
        match policy {
            Policy::Allow => Self::Accept,
            Policy::Deny => Self::Drop,
        }
    }
}

impl SetKey for Protocol {
    const LEN: u32 = 1;
    const TYPE: u32 = 12;

    fn data(&self) -> Box<[u8]> {
        Box::new([*self as u8])
    }
}

pub trait FirewallRule {
    fn to_chain_rule<'a>(
        &self,
        chain: &'a Chain,
        batch: &mut Batch,
    ) -> Result<Rule<'a>, FirewallError>;
}

fn add_address_to_set(set: *mut nftnl_sys::nftnl_set, ip: &Address) -> Result<(), FirewallError> {
    match ip {
        Address::Network(network) => {
            let upper_bound = max_address(network);
            let net = network.network();
            match (net, upper_bound) {
                (IpAddr::V4(network), IpAddr::V4(upper_bound)) => {
                    add_to_set(set, &network, Some(&upper_bound))?;
                }
                (IpAddr::V6(network), IpAddr::V6(upper_bound)) => {
                    add_to_set(set, &network, Some(&upper_bound))?;
                }
                _ => {
                    return Err(FirewallError::InvalidConfiguration(format!(
                        "Expected both addresses to be of the same type, got {net:?} and \
                        {upper_bound:?}",
                    )))
                }
            }
        }
        Address::Range(addr_range) => match addr_range {
            IpAddrRange::V4(ipv4_range) => {
                add_to_set(set, ipv4_range.start(), Some(ipv4_range.end()))?;
            }
            IpAddrRange::V6(ipv6_range) => {
                add_to_set(set, ipv6_range.start(), Some(ipv6_range.end()))?;
            }
        },
    }

    Ok(())
}

fn add_port_to_set(set: *mut nftnl_sys::nftnl_set, port: &Port) -> Result<(), FirewallError> {
    match port {
        Port::Any => {
            // nothing to do
        }
        Port::Single(port) => {
            let inet_service = InetService(*port);
            add_to_set(set, &inet_service, Some(&inet_service))?;
        }
        Port::Range(start, end) => {
            let start = InetService(*start);
            let end = InetService(*end);

            add_to_set(set, &start, Some(&end))?;
        }
    }

    Ok(())
}

fn add_protocol_to_set(
    set: *mut nftnl_sys::nftnl_set,
    proto: &Protocol,
) -> Result<(), FirewallError> {
    add_to_set(set, proto, None)?;
    Ok(())
}

fn add_rule_comment(rule: &mut Rule, comment: &str) -> Result<(), FirewallError> {
    debug!("Adding comment to nftables expression: {comment:?}");
    // Since we are interoping with C, truncate the string to 255 *bytes* (not UTF-8 characters)
    // 256 is the maximum length of a comment string in nftables, leave 1 byte for the null terminator
    let maybe_truncated_str = if comment.len() > 255 {
        warn!("Comment string {comment} is too long, truncating to 255 bytes");
        &comment[..=255]
    } else {
        comment
    };
    let comment = &CString::new(maybe_truncated_str).map_err(|e| {
        FirewallError::NetlinkError(format!(
            "Failed to create CString from string {comment}. Error: {e:?}"
        ))
    })?;
    rule.set_comment(comment);
    debug!("Added comment to nftables expression: {comment:?}");
    Ok(())
}

impl FirewallRule for FilterRule<'_> {
    fn to_chain_rule<'a>(
        &self,
        chain: &'a Chain,
        batch: &mut Batch,
    ) -> Result<Rule<'a>, FirewallError> {
        let mut rule = Rule::new(chain);
        debug!("Converting {self:?} to nftables expression");
        // Debug purposes only
        let mut matches = Vec::new();

        if !self.dest_ports.is_empty() && self.protocols.len() > 1 {
            return Err(FirewallError::InvalidConfiguration(format!(
                "Cannot specify multiple protocols with destination ports, specified \
                protocols: {:?}, destination ports: {:?}, Defguard Rule ID: {}",
                self.protocols, self.dest_ports, self.defguard_rule_id
            )));
        }

        // TODO: Reduce code duplication here
        if !self.src_ips.is_empty() {
            if self.v4 {
                let set = new_anon_set::<Ipv4Addr>(chain.get_table(), ProtoFamily::Inet, true)?;
                batch.add(&set, nftnl::MsgType::Add);

                for ip in self.src_ips {
                    add_address_to_set(set.as_ptr(), ip)?;
                }

                // ip saddr {x.x.x.x, x.x.x.x}
                set.elems_iter().for_each(|elem| {
                    batch.add(&elem, nftnl::MsgType::Add);
                });

                rule.add_expr(&nft_expr!(meta nfproto));
                rule.add_expr(&nft_expr!(cmp == libc::NFPROTO_IPV4 as u8));
                rule.add_expr(&nft_expr!(payload ipv4 saddr));

                rule.add_expr(&nft_expr!(lookup & set));
            } else {
                let set = new_anon_set::<Ipv6Addr>(chain.get_table(), ProtoFamily::Inet, true)?;
                batch.add(&set, nftnl::MsgType::Add);

                for ip in self.src_ips {
                    add_address_to_set(set.as_ptr(), ip)?;
                }

                // ip6 saddr {x.x.x.x, x.x.x.x}
                set.elems_iter().for_each(|elem| {
                    batch.add(&elem, nftnl::MsgType::Add);
                });

                rule.add_expr(&nft_expr!(meta nfproto));
                rule.add_expr(&nft_expr!(cmp == libc::NFPROTO_IPV6 as u8));
                rule.add_expr(&nft_expr!(payload ipv6 saddr));

                rule.add_expr(&nft_expr!(lookup & set));
            }
            debug!(
                "Added source IP addresses match to nftables expression: {:?}",
                self.src_ips
            );
            matches.push(format!("ANY SOURCE IPs: {:?}", self.src_ips));
        }

        // TODO: Reduce code duplication here
        if !self.dest_ips.is_empty() {
            if self.v4 {
                let set = new_anon_set::<Ipv4Addr>(chain.get_table(), ProtoFamily::Inet, true)?;
                batch.add(&set, nftnl::MsgType::Add);

                for ip in self.dest_ips {
                    add_address_to_set(set.as_ptr(), ip)?;
                }

                set.elems_iter().for_each(|elem| {
                    batch.add(&elem, nftnl::MsgType::Add);
                });

                // ip daddr {x.x.x.x, x.x.x.x}
                rule.add_expr(&nft_expr!(meta nfproto));
                rule.add_expr(&nft_expr!(cmp == libc::NFPROTO_IPV4 as u8));
                rule.add_expr(&nft_expr!(payload ipv4 daddr));

                rule.add_expr(&nft_expr!(lookup & set));
            } else {
                let set = new_anon_set::<Ipv6Addr>(chain.get_table(), ProtoFamily::Inet, true)?;
                batch.add(&set, nftnl::MsgType::Add);

                for ip in self.dest_ips {
                    add_address_to_set(set.as_ptr(), ip)?;
                }

                // ip6 daddr {x.x.x.x, x.x.x.x}
                set.elems_iter().for_each(|elem| {
                    batch.add(&elem, nftnl::MsgType::Add);
                });

                rule.add_expr(&nft_expr!(meta nfproto));
                rule.add_expr(&nft_expr!(cmp == libc::NFPROTO_IPV6 as u8));
                rule.add_expr(&nft_expr!(payload ipv6 daddr));

                rule.add_expr(&nft_expr!(lookup & set));
            }
            debug!(
                "Added destination IP addresses match to nftables expression: {:?}",
                self.dest_ips
            );
            matches.push(format!("ANY DEST IPs: {:?}", self.dest_ips));
        }

        if !self.protocols.is_empty() {
            // > 0 Protocols
            // 0 Ports
            if self.protocols.len() > 1 {
                let set = new_anon_set::<Protocol>(chain.get_table(), ProtoFamily::Inet, false)?;
                batch.add(&set, nftnl::MsgType::Add);

                for proto in &self.protocols {
                    add_protocol_to_set(set.as_ptr(), proto)?;
                }

                // <protocol> dport {x, x-x}
                set.elems_iter().for_each(|elem| {
                    batch.add(&elem, nftnl::MsgType::Add);
                });

                rule.add_expr(&nft_expr!(meta nfproto));

                if self.v4 {
                    rule.add_expr(&nft_expr!(cmp == libc::NFPROTO_IPV4 as u8));
                    rule.add_expr(&nft_expr!(payload ipv4 protocol));
                } else {
                    rule.add_expr(&nft_expr!(cmp == libc::NFPROTO_IPV6 as u8));
                    rule.add_expr(&nft_expr!(payload ipv6 nextheader));
                }

                rule.add_expr(&nft_expr!(lookup & set));

                debug!("Added protocol match to rule: {:?}", self.protocols);
                matches.push(format!("ANY PROTOCOLS: {:?}", self.protocols));
            }
            // 1 Protocol
            // > 0 Ports
            else if !self.dest_ports.is_empty() {
                if let Some(protocol) = self.protocols.first() {
                    if protocol.supports_ports() {
                        let set = new_anon_set::<InetService>(
                            chain.get_table(),
                            ProtoFamily::Inet,
                            true,
                        )?;
                        batch.add(&set, nftnl::MsgType::Add);

                        for port in self.dest_ports {
                            add_port_to_set(set.as_ptr(), port)?;
                        }

                        // <protocol> dport {x, x-x}
                        set.elems_iter().for_each(|elem| {
                            batch.add(&elem, nftnl::MsgType::Add);
                        });

                        rule.add_expr(&nft_expr!(meta l4proto));
                        rule.add_expr(&nft_expr!(cmp == *protocol as u8));
                        rule.add_expr(protocol.as_port_payload_expr()?);
                        rule.add_expr(&nft_expr!(lookup & set));
                    }
                }

                debug!(
                    "Added single protocol ({:?}) match and destination ports match to nftables \
                    expression: {:?}",
                    self.protocols, self.dest_ports
                );
                matches.push(format!(
                    "PROTOCOL: {:?} AND ANY DEST PORTS: {:?}",
                    self.protocols, self.dest_ports
                ));
            }
            // 1 Protocol
            // 0 Ports
            else if let Some(protocol) = self.protocols.first() {
                // ip protocol <protocol>
                rule.add_expr(&nft_expr!(meta nfproto));

                if self.v4 {
                    rule.add_expr(&nft_expr!(cmp == libc::NFPROTO_IPV4 as u8));
                    rule.add_expr(&nft_expr!(payload ipv4 protocol));
                } else {
                    rule.add_expr(&nft_expr!(cmp == libc::NFPROTO_IPV6 as u8));
                    rule.add_expr(&nft_expr!(payload ipv6 nextheader));
                }

                rule.add_expr(&nft_expr!(cmp == *protocol as u8));
                debug!("Added protocol match to rule: {protocol:?}");
                matches.push(format!("SINGLE PROTOCOL: {protocol:?}"));
            }
        }

        if let Some(iifname) = &self.iifname {
            // iifname <interface>
            rule.add_expr(&nft_expr!(meta iifname));
            let exact = InterfaceName::Exact(CString::new(iifname.as_str()).unwrap());
            if self.negated_iifname {
                rule.add_expr(&nft_expr!(cmp != exact));
            } else {
                rule.add_expr(&nft_expr!(cmp == exact));
            }
            debug!("Added input interface match to rule: {iifname:?}");
            matches.push(format!("INPUT INTERFACE: {iifname:?}"));
        }

        if let Some(oifname) = &self.oifname {
            // oifname <interface>
            rule.add_expr(&nft_expr!(meta oifname));
            let exact = InterfaceName::Exact(CString::new(oifname.as_str()).unwrap());
            if self.negated_oifname {
                rule.add_expr(&nft_expr!(cmp != exact));
            } else {
                rule.add_expr(&nft_expr!(cmp == exact));
            }
            debug!("Added output interface match to rule: {oifname:?}");
            matches.push(format!("OUTPUT INTERFACE: {oifname:?}"));
        }

        if !self.states.is_empty() {
            // ct state <state1>,<state2>
            let combined_states = self
                .states
                .iter()
                .fold(0u32, |acc, state| acc | state.to_expr_state().bits());
            rule.add_expr(&nft_expr!(ct state));
            rule.add_expr(&nft_expr!(bitwise mask combined_states, xor 0u32));
            rule.add_expr(&nft_expr!(cmp != 0u32));
            debug!(
                "Added connection tracking states match to nftables expression: {:?}",
                self.states
            );
            matches.push(format!("ANY CT STATES: {:?}", self.states));
        }

        if self.counter {
            // counter
            rule.add_expr(&nft_expr!(counter));
            debug!("Added counter expression to rule");
        }

        // accept/drop
        match self.action {
            Policy::Allow => {
                rule.add_expr(&nft_expr!(verdict accept));
            }
            Policy::Deny => {
                rule.add_expr(&nft_expr!(verdict drop));
            }
        }

        // comment <comment>
        if let Some(comment_string) = &self.comment {
            add_rule_comment(&mut rule, comment_string)?;
        } else {
            debug!("No comment provided for nftables expression");
        }

        let matches = matches.join(" AND ");
        debug!("Created nftables rule with matches: {matches:?}");

        Ok(rule)
    }
}

#[derive(Debug)]
struct MasqueradeRule {
    oifname: String,
    negated_oifname: bool,
    counter: bool,
}

impl FirewallRule for MasqueradeRule {
    fn to_chain_rule<'a>(
        &self,
        chain: &'a Chain,
        _batch: &mut Batch,
    ) -> Result<Rule<'a>, FirewallError> {
        let mut rule = Rule::new(chain);

        rule.add_expr(&nft_expr!(meta oifname));
        let exact = InterfaceName::Exact(CString::new(self.oifname.as_str()).unwrap());
        if self.negated_oifname {
            rule.add_expr(&nft_expr!(cmp != exact));
        } else {
            rule.add_expr(&nft_expr!(cmp == exact));
        }

        if self.counter {
            rule.add_expr(&nft_expr!(counter));
        }

        rule.add_expr(&nft_expr!(masquerade));

        Ok(rule)
    }
}

#[derive(Debug)]
struct SnatRule<'a> {
    src_ips: &'a [Address],
    public_ip: &'a IpAddr,
    oifname: String,
    negated_oifname: bool,
    counter: bool,
    ipv4: bool,
    comment: Option<String>,
}

impl FirewallRule for SnatRule<'_> {
    fn to_chain_rule<'a>(
        &self,
        chain: &'a Chain,
        batch: &mut Batch,
    ) -> Result<Rule<'a>, FirewallError> {
        let mut rule = Rule::new(chain);

        if !self.src_ips.is_empty() {
            if self.ipv4 {
                let set = new_anon_set::<Ipv4Addr>(chain.get_table(), ProtoFamily::Inet, true)?;
                batch.add(&set, nftnl::MsgType::Add);

                for ip in self.src_ips {
                    add_address_to_set(set.as_ptr(), ip)?;
                }

                // ip saddr {x.x.x.x, x.x.x.x}
                set.elems_iter().for_each(|elem| {
                    batch.add(&elem, nftnl::MsgType::Add);
                });

                rule.add_expr(&nft_expr!(meta nfproto));
                rule.add_expr(&nft_expr!(cmp == libc::NFPROTO_IPV4 as u8));
                rule.add_expr(&nft_expr!(payload ipv4 saddr));

                rule.add_expr(&nft_expr!(lookup & set));
            } else {
                let set = new_anon_set::<Ipv6Addr>(chain.get_table(), ProtoFamily::Inet, true)?;
                batch.add(&set, nftnl::MsgType::Add);

                for ip in self.src_ips {
                    add_address_to_set(set.as_ptr(), ip)?;
                }

                // ip6 saddr {x.x.x.x, x.x.x.x}
                set.elems_iter().for_each(|elem| {
                    batch.add(&elem, nftnl::MsgType::Add);
                });

                rule.add_expr(&nft_expr!(meta nfproto));
                rule.add_expr(&nft_expr!(cmp == libc::NFPROTO_IPV6 as u8));
                rule.add_expr(&nft_expr!(payload ipv6 saddr));

                rule.add_expr(&nft_expr!(lookup & set));
            }
            debug!(
                "Added source IP addresses match to nftables expression: {:?}",
                self.src_ips
            );
        }

        rule.add_expr(&nft_expr!(meta oifname));
        let exact = InterfaceName::Exact(CString::new(self.oifname.as_str()).unwrap());
        if self.negated_oifname {
            rule.add_expr(&nft_expr!(cmp != exact));
        } else {
            rule.add_expr(&nft_expr!(cmp == exact));
        }

        if self.counter {
            rule.add_expr(&nft_expr!(counter));
        }

        // determine if public IP is IPv4 or IPv6 and store the address in a register
        let family = match self.public_ip {
            IpAddr::V4(ipv4_addr) => {
                rule.add_expr(&Immediate::new(*ipv4_addr, Register::Reg1));
                ProtoFamily::Ipv4
            }
            IpAddr::V6(ipv6_addr) => {
                rule.add_expr(&Immediate::new(*ipv6_addr, Register::Reg1));
                ProtoFamily::Ipv6
            }
        };
        let snat_expr = Nat {
            nat_type: NatType::SNat,
            family,
            ip_register: Register::Reg1,
            port_register: None,
        };

        rule.add_expr(&snat_expr);

        // comment <comment>
        if let Some(comment_string) = &self.comment {
            add_rule_comment(&mut rule, comment_string)?;
        } else {
            debug!("No comment provided for nftables expression");
        }

        Ok(rule)
    }
}

// Left in case if this is ever needed
// struct JumpRule<'a> {
//     src_chain: &'a Chain<'a>,
//     dest_chain: &'a Chain<'a>,
//     oifname: Option<String>,
//     iifname: Option<String>,
//     negated_oifname: bool,
//     negated_iifname: bool,
// }

// impl<'a> JumpRule<'a> {
//     fn to_chain_rule(&self) -> Result<Rule<'a>, FirewallError> {
//         let mut rule = Rule::new(self.src_chain);

//         if let Some(iifname) = &self.iifname {
//             rule.add_expr(&nft_expr!(meta iifname));
//             let exact = InterfaceName::Exact(CString::new(iifname.as_str()).unwrap());
//             if self.negated_iifname {
//                 rule.add_expr(&nft_expr!(cmp != exact));
//             } else {
//                 rule.add_expr(&nft_expr!(cmp == exact));
//             }
//         }

//         if let Some(oifname) = &self.oifname {
//             rule.add_expr(&nft_expr!(meta oifname));
//             let exact = InterfaceName::Exact(CString::new(oifname.as_str()).unwrap());
//             if self.negated_oifname {
//                 rule.add_expr(&nft_expr!(cmp != exact));
//             } else {
//                 rule.add_expr(&nft_expr!(cmp == exact));
//             }
//         }

//         // first, match

//         rule.add_expr(&nft_expr!(counter));
//         rule.add_expr(&nft_expr!(verdict jump self.dest_chain.get_name().into()));

//         Ok(rule)
//     }
// }

/// Sets up the default chains for the firewall
pub(super) fn init_firewall(
    initial_policy: Policy,
    defguard_fwd_chain_priority: Option<i32>,
    batch: &mut Batch,
    ifname: &str,
) -> Result<(), FirewallError> {
    let table = Tables::Defguard(ProtoFamily::Inet).to_table(ifname);

    batch.add(&table, nftnl::MsgType::Add);
    batch.add(&table, nftnl::MsgType::Del);
    batch.add(&table, nftnl::MsgType::Add);

    let mut fw_chain = Chains::Forward.to_chain(&table);
    fw_chain.set_hook(
        nftnl::Hook::Forward,
        defguard_fwd_chain_priority.unwrap_or(FORWARD_PRIORITY),
    );
    fw_chain.set_policy(initial_policy.into());
    fw_chain.set_type(nftnl::ChainType::Filter);
    batch.add(&fw_chain, nftnl::MsgType::Add);

    Ok(())
}

pub(super) fn drop_table(batch: &mut Batch, ifname: &str) -> Result<(), FirewallError> {
    let table = Tables::Defguard(ProtoFamily::Inet).to_table(ifname);
    batch.add(&table, nftnl::MsgType::Add);
    batch.add(&table, nftnl::MsgType::Del);

    Ok(())
}

pub(super) fn drop_chain(
    chain: &Chains,
    batch: &mut Batch,
    ifname: &str,
) -> Result<(), FirewallError> {
    let table = Tables::Defguard(ProtoFamily::Inet).to_table(ifname);
    let chain = chain.to_chain(&table);
    batch.add(&chain, nftnl::MsgType::Add);
    batch.add(&chain, nftnl::MsgType::Del);

    Ok(())
}

/// Applies NAT rules on the specified interface for the outgoing packets
pub(super) fn set_nat_rules(
    batch: &mut Batch,
    ifname: &str,
    masquerade_enabled: bool,
    snat_bindings: &[SnatBinding],
) -> Result<(), FirewallError> {
    // cleanup existing POSTROUTING chain rules
    let table = Tables::Defguard(ProtoFamily::Inet).to_table(ifname);
    batch.add(&table, nftnl::MsgType::Add);

    drop_chain(&Chains::Postrouting, batch, ifname)?;

    // initialize new POSTROUTING chain
    let mut nat_chain = Chains::Postrouting.to_chain(&table);
    nat_chain.set_hook(nftnl::Hook::PostRouting, POSTROUTING_PRIORITY);
    nat_chain.set_policy(nftnl::Policy::Accept);
    nat_chain.set_type(nftnl::ChainType::Nat);
    batch.add(&nat_chain, nftnl::MsgType::Add);

    // add SNAT bindings
    for binding in snat_bindings {
        let snat_rule = SnatRule {
            oifname: LOOPBACK_IFACE.to_string(),
            negated_oifname: true,
            counter: true,
            src_ips: &binding.source_addrs,
            public_ip: &binding.public_ip,
            ipv4: binding.public_ip.is_ipv4(),
            comment: binding.comment.clone(),
        }
        .to_chain_rule(&nat_chain, batch)?;

        batch.add(&snat_rule, nftnl::MsgType::Add);
    }

    // add MASQUERADE rule
    let masquerade_rule = MasqueradeRule {
        oifname: LOOPBACK_IFACE.to_string(),
        negated_oifname: true,
        counter: true,
    }
    .to_chain_rule(&nat_chain, batch)?;

    if masquerade_enabled {
        batch.add(&masquerade_rule, nftnl::MsgType::Add);
    } else {
        batch.add(&masquerade_rule, nftnl::MsgType::Del);
    }

    Ok(())
}

// pub(super) fn set_default_policy(
//     policy: Policy,
//     batch: &mut Batch,
//     ifname: &str,
// ) -> Result<(), FirewallError> {
//     let table = Tables::Defguard(ProtoFamily::Inet).to_table(ifname);
//     batch.add(&table, nftnl::MsgType::Add);

//     let mut forward_chain = Chains::Forward.to_chain(&table);
//     forward_chain.set_policy(if policy == Policy::Allow {
//         nftnl::Policy::Accept
//     } else {
//         nftnl::Policy::Drop
//     });
//     batch.add(&forward_chain, nftnl::MsgType::Add);

//     Ok(())
// }

pub(super) fn allow_established_traffic(
    batch: &mut Batch,
    ifname: &str,
) -> Result<(), FirewallError> {
    let table = Tables::Defguard(ProtoFamily::Inet).to_table(ifname);
    batch.add(&table, nftnl::MsgType::Add);

    let forward_chain = Chains::Forward.to_chain(&table);
    batch.add(&forward_chain, nftnl::MsgType::Add);

    let established_rule = FilterRule {
        states: vec![State::Established, State::Related],
        counter: true,
        action: Policy::Allow,
        comment: Some("Allow established and related traffic".to_string()),
        ..Default::default()
    }
    .to_chain_rule(&forward_chain, batch)?;
    batch.add(&established_rule, nftnl::MsgType::Add);

    Ok(())
}

pub(super) fn ignore_unrelated_traffic(
    batch: &mut Batch,
    ifname: &str,
) -> Result<(), FirewallError> {
    let table = Tables::Defguard(ProtoFamily::Inet).to_table(ifname);
    batch.add(&table, nftnl::MsgType::Add);

    let forward_chain = Chains::Forward.to_chain(&table);
    batch.add(&forward_chain, nftnl::MsgType::Add);

    let ignore_rule = FilterRule {
        iifname: Some(ifname.to_string()),
        negated_iifname: true,
        action: Policy::Allow,
        counter: true,
        comment: Some("Ignore traffic not related to the VPN".to_string()),
        ..Default::default()
    }
    .to_chain_rule(&forward_chain, batch)?;
    batch.add(&ignore_rule, nftnl::MsgType::Add);

    Ok(())
}

#[allow(dead_code)]
enum Tables {
    Filter(ProtoFamily),
    Nat(ProtoFamily),
    Defguard(ProtoFamily),
}

impl Tables {
    fn to_table(&self, ifname: &str) -> Table {
        match self {
            Self::Filter(family) => Table::new(
                &CString::new(FILTER_TABLE)
                    .expect("Failed to create CString from FILTER_TABLE constant."),
                *family,
            ),
            Self::Nat(family) => Table::new(
                &CString::new(NAT_TABLE)
                    .expect("Failed to create CString from NAT_TABLE constant."),
                *family,
            ),
            Self::Defguard(family) => Table::new(
                &CString::new(DEFGUARD_TABLE.to_owned() + ifname)
                    .expect("Failed to create CString from DEFGUARD_TABLE constant."),
                *family,
            ),
        }
    }
}

pub(super) enum Chains {
    Forward,
    Postrouting,
}

impl Chains {
    fn to_chain<'a>(&self, table: &'a Table) -> Chain<'a> {
        match self {
            Self::Forward => Chain::new(
                &CString::new(FORWARD_CHAIN)
                    .expect("Failed to create CString from FORWARD_CHAIN constant."),
                table,
            ),
            Self::Postrouting => Chain::new(
                &CString::new(POSTROUTING_CHAIN)
                    .expect("Failed to create CString from POSTROUTING_CHAIN constant."),
                table,
            ),
        }
    }
}

pub(super) fn apply_filter_rules(
    rules: Vec<FilterRule>,
    batch: &mut Batch,
    ifname: &str,
) -> Result<(), FirewallError> {
    let table = Tables::Defguard(ProtoFamily::Inet).to_table(ifname);
    batch.add(&table, nftnl::MsgType::Add);

    let forward_chain = Chains::Forward.to_chain(&table);
    batch.add(&forward_chain, nftnl::MsgType::Add);

    for rule in rules.iter() {
        let chain_rule = rule.to_chain_rule(&forward_chain, batch)?;
        batch.add(&chain_rule, nftnl::MsgType::Add);
    }

    Ok(())
}

pub(crate) fn send_batch(batch: &FinalizedBatch) -> Result<(), FirewallError> {
    let socket = mnl::Socket::new(mnl::Bus::Netfilter)
        .map_err(|e| FirewallError::NetlinkError(format!("Failed to create socket: {e:?}")))?;
    socket.send_all(batch).map_err(|e| {
        FirewallError::NetlinkError(format!("Failed to send batch through socket: {e:?}"))
    })?;

    let portid = socket.portid();
    let mut buffer = vec![0; nftnl::nft_nlmsg_maxsize() as usize];

    // TODO: Why is it supposed to be 2?
    let seq = 2;
    while let Some(message) = socket_recv(&socket, &mut buffer[..])? {
        match mnl::cb_run(message, seq, portid) {
            Ok(mnl::CbResult::Stop) => {
                debug!("Received stop signal from netlink callback");
                break;
            }
            Ok(mnl::CbResult::Ok) => {
                debug!("Received OK signal from netlink callback");
            }
            Err(err) => {
                return Err(FirewallError::NetlinkError(format!(
                    "There was an error while sending netlink messages: {err:?}"
                )))
            }
        };
    }

    Ok(())
}

fn socket_recv<'a>(
    socket: &mnl::Socket,
    buf: &'a mut [u8],
) -> Result<Option<&'a [u8]>, FirewallError> {
    let ret = socket.recv(buf).map_err(|err| {
        FirewallError::NetlinkError(format!(
            "Failed while reading a message from socket: {err:?}"
        ))
    })?;
    if ret > 0 {
        Ok(Some(&buf[..ret]))
    } else {
        Ok(None)
    }
}

/// Get the max address in a network.
///
/// - In IPv4 this is the broadcast address.
/// - In IPv6 this is just the last address in the network.
fn max_address(network: &IpNetwork) -> IpAddr {
    match network {
        IpNetwork::V4(network) => {
            let addr = network.ip().to_bits();
            let mask = network.mask().to_bits();

            IpAddr::V4(Ipv4Addr::from(addr | !mask))
        }
        IpNetwork::V6(network) => {
            let addr = network.ip().to_bits();
            let mask = network.mask().to_bits();

            IpAddr::V6(Ipv6Addr::from(addr | !mask))
        }
    }
}

fn new_anon_set<T>(
    table: &Table,
    family: ProtoFamily,
    interval_set: bool,
) -> Result<Set<T>, FirewallError>
where
    T: SetKey,
{
    let set = Set::<T>::new(ANON_SET_NAME, get_set_id(), table, family);

    if interval_set {
        unsafe {
            nftnl_sys::nftnl_set_set_u32(
                set.as_ptr(),
                nftnl_sys::NFTNL_SET_FLAGS as u16,
                (libc::NFT_SET_ANONYMOUS | libc::NFT_SET_CONSTANT | libc::NFT_SET_INTERVAL) as u32,
            );
        }
    }

    Ok(set)
}

/// Adds key to a set. If the range_end option is specified, it will assume the lower and upper
/// bounds of a range need to be added.
fn add_to_set<K>(
    set: *mut nftnl_sys::nftnl_set,
    key: &K,
    range_end: Option<&K>,
) -> Result<(), FirewallError>
where
    K: SetKey,
{
    let key_data = key.data();
    let key_data_len = key_data.len() as u32;
    unsafe {
        let elem = nftnl_sys::nftnl_set_elem_alloc();
        if elem.is_null() {
            return Err(FirewallError::OutOfMemory(
                "Failed to allocate memory for set element".to_string(),
            ));
        }
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
            if elem.is_null() {
                return Err(FirewallError::OutOfMemory(
                    "Failed to allocate memory for set element".to_string(),
                ));
            }
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

    Ok(())
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
