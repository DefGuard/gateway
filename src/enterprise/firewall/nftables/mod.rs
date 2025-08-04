pub mod netfilter;

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::atomic::{AtomicU32, Ordering},
};

use netfilter::{
    allow_established_traffic, apply_filter_rules, drop_table, ignore_unrelated_traffic,
    init_firewall, send_batch, set_masq,
};
use nftnl::Batch;

use super::{
    api::{FirewallApi, FirewallManagementApi},
    Address, FirewallError, FirewallRule, Policy, Port, Protocol,
};
use crate::enterprise::firewall::iprange::IpAddrRange;

static SET_ID_COUNTER: AtomicU32 = AtomicU32::new(0);

pub fn get_set_id() -> u32 {
    SET_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

#[allow(dead_code)]
#[derive(Debug, Default)]
enum State {
    #[default]
    Established,
    Invalid,
    New,
    Related,
}

#[derive(Debug, Default)]
struct FilterRule<'a> {
    src_ips: &'a [Address],
    dest_ips: &'a [Address],
    // src_ports: &'a [Port],
    dest_ports: &'a [Port],
    protocols: Vec<Protocol>,
    oifname: Option<String>,
    iifname: Option<String>,
    action: Policy,
    states: Vec<State>,
    counter: bool,
    // The ID of the associated Defguard rule.
    // The filter rules may not always be a 1:1 representation of the Defguard rules, so
    // this value helps to keep track of them.
    defguard_rule_id: i64,
    v4: bool,
    comment: Option<String>,
    negated_oifname: bool,
    negated_iifname: bool,
}

fn merge_addrs<'a>(addrs: &'a [Address]) -> Vec<Address> {
    debug!("merge_addrs called with input: {:?}", addrs);

    if addrs.is_empty() {
        debug!("No addresses provided, returning empty vector.");
        return Vec::new();
    }

    let mut merged_addrs = Vec::new();

    // sort them by their .first() address
    let mut addrs_sorted = Vec::from_iter(addrs.iter());
    addrs_sorted.sort_by(|a, b| {
        a.first()
            .partial_cmp(&b.first())
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    debug!("Sorted addresses: {:?}", addrs_sorted);

    let first_addr = addrs_sorted.remove(0);
    let mut current_range_start = first_addr.first();
    let mut current_range_end = first_addr.last();

    debug!(
        "Starting merge loop with initial range: {:?} - {:?}",
        current_range_start, current_range_end
    );

    for addr in addrs_sorted {
        let first_addr = addr.first();
        let last_addr = addr.last();

        debug!(
            "Checking addr: {:?} - {:?} against current_range_end: {:?}",
            first_addr, last_addr, current_range_end
        );

        // Check if ranges overlap or are adjacent
        if first_addr <= current_range_end || next_ip(current_range_end) == first_addr {
            // Ranges overlap or are adjacent, merge them
            if last_addr > current_range_end {
                debug!(
                    "Extending current_range_end from {:?} to {:?}",
                    current_range_end, last_addr
                );
                current_range_end = last_addr;
            }
        } else {
            // Ranges don't overlap and aren't adjacent, push current range and start new one
            debug!(
                "Pushing merged range: {:?} - {:?}",
                current_range_start, current_range_end
            );
            merged_addrs.push(Address::Range(
                IpAddrRange::new(current_range_start, current_range_end).unwrap(),
            ));
            current_range_start = first_addr;
            current_range_end = last_addr;
        }
    }

    // Push the last range
    debug!(
        "Pushing final merged range: {:?} - {:?}",
        current_range_start, current_range_end
    );
    merged_addrs.push(Address::Range(
        IpAddrRange::new(current_range_start, current_range_end).unwrap(),
    ));

    debug!("Prepared addresses: {:?}", merged_addrs);

    merged_addrs
}

/// Returns the next IP address in sequence, handling overflow via wrapping
fn next_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            let mut num: u32 = ((octets[0] as u32) << 24)
                | ((octets[1] as u32) << 16)
                | ((octets[2] as u32) << 8)
                | octets[3] as u32;
            num = num.wrapping_add(1);
            IpAddr::V4(Ipv4Addr::from(num))
        }
        IpAddr::V6(ipv6) => {
            let segments = ipv6.segments();
            let mut num: u128 = ((segments[0] as u128) << 112)
                | ((segments[1] as u128) << 96)
                | ((segments[2] as u128) << 80)
                | ((segments[3] as u128) << 64)
                | ((segments[4] as u128) << 48)
                | ((segments[5] as u128) << 32)
                | ((segments[6] as u128) << 16)
                | segments[7] as u128;
            num = num.wrapping_add(1);
            IpAddr::V6(Ipv6Addr::from(num))
        }
    }
}

impl FirewallApi {
    fn add_rule(&mut self, rule: FirewallRule) -> Result<(), FirewallError> {
        debug!("Applying the following Defguard ACL rule: {rule:?}");
        let batch = if let Some(ref mut batch) = self.batch {
            batch
        } else {
            return Err(FirewallError::TransactionNotStarted);
        };

        let mut filter_rules = Vec::new();
        debug!(
            "The rule will be split into multiple nftables rules based on the specified \
            destination ports and protocols."
        );

        let source_addrs = merge_addrs(&rule.source_addrs);
        let dest_addrs = merge_addrs(&rule.destination_addrs);

        if rule.destination_ports.is_empty() {
            debug!(
                "No destination ports specified, applying single aggregate nftables rule for \
                every protocol."
            );
            let rule = FilterRule {
                src_ips: &source_addrs,
                dest_ips: &dest_addrs,
                protocols: rule.protocols.clone(),
                action: rule.verdict,
                counter: true,
                defguard_rule_id: rule.id,
                v4: rule.ipv4,
                comment: rule.comment.clone(),
                ..Default::default()
            };
            filter_rules.push(rule);
        } else if !rule.protocols.is_empty() {
            debug!(
                "Destination ports and protocols specified, applying individual nftables rules \
                for each protocol."
            );
            for protocol in rule.protocols.clone() {
                debug!("Applying rule for protocol: {protocol:?}");
                if protocol.supports_ports() {
                    debug!("Protocol supports ports, rule.");
                    let rule = FilterRule {
                        src_ips: &source_addrs,
                        dest_ips: &dest_addrs,
                        dest_ports: &rule.destination_ports,
                        protocols: vec![protocol],
                        action: rule.verdict,
                        counter: true,
                        defguard_rule_id: rule.id,
                        v4: rule.ipv4,
                        comment: rule.comment.clone(),
                        ..Default::default()
                    };
                    filter_rules.push(rule);
                } else {
                    debug!(
                        "Protocol does not support ports, applying nftables rule and ignoring \
                        destination ports."
                    );
                    let rule = FilterRule {
                        src_ips: &source_addrs,
                        dest_ips: &dest_addrs,
                        protocols: vec![protocol],
                        action: rule.verdict,
                        counter: true,
                        defguard_rule_id: rule.id,
                        v4: rule.ipv4,
                        comment: rule.comment.clone(),
                        ..Default::default()
                    };
                    filter_rules.push(rule);
                }
            }
        } else {
            debug!(
                "Destination ports specified, but no protocols specified, applying nftables rules \
                for each protocol that support ports."
            );
            for protocol in [Protocol::Tcp, Protocol::Udp] {
                debug!("Applying nftables rule for protocol: {protocol:?}");
                let rule = FilterRule {
                    src_ips: &source_addrs,
                    dest_ips: &dest_addrs,
                    dest_ports: &rule.destination_ports,
                    protocols: vec![protocol],
                    action: rule.verdict,
                    counter: true,
                    defguard_rule_id: rule.id,
                    v4: rule.ipv4,
                    comment: rule.comment.clone(),
                    ..Default::default()
                };
                filter_rules.push(rule);
            }
        }

        apply_filter_rules(filter_rules, batch, &self.ifname)?;

        debug!(
            "Applied firewall rules for Defguard ACL rule ID: {}",
            rule.id
        );
        Ok(())
    }
}

impl FirewallManagementApi for FirewallApi {
    /// Sets up the firewall with the given default policy and priority. Drops the previous table.
    ///
    /// This function also begins a batch of operations which can be applied later using the [`apply`] method.
    /// This allows for making atomic changes to the firewall rules.
    fn setup(
        &mut self,
        default_policy: Policy,
        priority: Option<i32>,
    ) -> Result<(), FirewallError> {
        debug!("Initializing firewall, VPN interface: {}", self.ifname);
        if let Some(batch) = &mut self.batch {
            drop_table(batch, &self.ifname)?;
            init_firewall(default_policy, priority, batch, &self.ifname)
                .expect("Failed to setup chains");
            debug!("Allowing all established traffic");
            ignore_unrelated_traffic(batch, &self.ifname)?;
            allow_established_traffic(batch, &self.ifname)?;
            debug!("Allowed all established traffic");
            debug!("Initialized firewall");
            Ok(())
        } else {
            Err(FirewallError::TransactionNotStarted)
        }
    }

    /// Cleans up the whole Defguard table.
    fn cleanup(&mut self) -> Result<(), FirewallError> {
        debug!("Cleaning up all previous firewall rules, if any");
        if let Some(batch) = &mut self.batch {
            drop_table(batch, &self.ifname)?;
        } else {
            return Err(FirewallError::TransactionNotStarted);
        }
        debug!("Cleaned up all previous firewall rules");
        Ok(())
    }

    // Allows for changing the default policy of the firewall.
    // fn set_firewall_default_policy(&mut self, policy: Policy) -> Result<(), FirewallError> {
    //     debug!("Setting default firewall policy to: {policy:?}");
    //     if let Some(batch) = &mut self.batch {
    //         set_default_policy(policy, batch, &self.ifname)?;
    //     } else {
    //         return Err(FirewallError::TransactionNotStarted);
    //     }
    //     debug!("Set firewall default policy to {policy:?}");
    //     Ok(())
    // }

    /// Allows for changing the masquerade status of the firewall.
    fn set_masquerade_status(&mut self, enabled: bool) -> Result<(), FirewallError> {
        debug!("Setting masquerade status to: {enabled:?}");
        if let Some(batch) = &mut self.batch {
            set_masq(&self.ifname, enabled, batch)?;
        } else {
            return Err(FirewallError::TransactionNotStarted);
        }
        debug!("Set masquerade status to: {enabled:?}");
        Ok(())
    }

    fn add_rules(&mut self, rules: Vec<FirewallRule>) -> Result<(), FirewallError> {
        debug!("Applying the following Defguard ACL rules: {rules:?}");
        for rule in rules {
            self.add_rule(rule)?;
        }
        debug!("Applied all Defguard ACL rules");
        Ok(())
    }

    fn begin(&mut self) -> Result<(), FirewallError> {
        if self.batch.is_none() {
            debug!("Starting new firewall transaction");
            let batch = Batch::new();
            self.batch = Some(batch);
            debug!("Firewall transaction successfully started");
            Ok(())
        } else {
            Err(FirewallError::TransactionFailed(
                "There is another firewall transaction already in progress. Commit or \
                rollback it before starting a new one."
                    .to_string(),
            ))
        }
    }

    /// Apply whole firewall configuration and send it in one go to the kernel.
    fn commit(&mut self) -> Result<(), FirewallError> {
        if let Some(batch) = self.batch.take() {
            debug!("Committing firewall transaction");
            let finalized = batch.finalize();
            debug!("Firewall batch finalized, sending to kernel");
            send_batch(&finalized)?;
            debug!("Firewall transaction successfully committed to kernel");
            Ok(())
        } else {
            Err(FirewallError::TransactionNotStarted)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ipnetwork::IpNetwork;

    use super::*;
    use crate::proto::enterprise::firewall::FirewallRule as ProtoFirewallRule;

    #[test]
    fn test_sorting() {
        let mut addrs = vec![
            Address::Network(IpNetwork::from_str("10.10.10.11/24").unwrap()),
            Address::Network(IpNetwork::from_str("10.10.10.12/24").unwrap()),
            Address::Network(IpNetwork::from_str("10.10.11.10/32").unwrap()),
            Address::Network(IpNetwork::from_str("10.10.11.11/32").unwrap()),
            Address::Network(IpNetwork::from_str("10.10.10.10/24").unwrap()),
            Address::Network(IpNetwork::from_str("10.10.11.12/32").unwrap()),
        ];

        addrs.sort_by(|a, b| {
            a.first()
                .partial_cmp(&b.first())
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        assert_eq!(
            addrs,
            vec![
                Address::Network(IpNetwork::from_str("10.10.10.10/24").unwrap()),
                Address::Network(IpNetwork::from_str("10.10.10.11/24").unwrap()),
                Address::Network(IpNetwork::from_str("10.10.10.12/24").unwrap()),
                Address::Network(IpNetwork::from_str("10.10.11.10/32").unwrap()),
                Address::Network(IpNetwork::from_str("10.10.11.11/32").unwrap()),
                Address::Network(IpNetwork::from_str("10.10.11.12/32").unwrap()),
            ]
        );

        let _prepared_addrs = merge_addrs(&addrs);
    }

    #[test]
    fn test_merge_addrs_empty() {
        let addrs: Vec<Address> = vec![];
        let result = merge_addrs(&addrs);
        assert!(result.is_empty());
    }

    #[test]
    fn test_merge_addrs_single_address() {
        let addrs = vec![Address::Network(
            IpNetwork::from_str("192.168.1.10/32").unwrap(),
        )];
        let result = merge_addrs(&addrs);

        assert_eq!(result.len(), 1);
        if let Address::Range(range) = &result[0] {
            assert_eq!(range.start(), IpAddr::from_str("192.168.1.10").unwrap());
            assert_eq!(range.end(), IpAddr::from_str("192.168.1.10").unwrap());
        } else {
            panic!("Expected Address::Range");
        }
    }

    #[test]
    fn test_merge_addrs_overlapping_ranges() {
        let addrs = vec![
            Address::Range(
                IpAddrRange::new(
                    IpAddr::from_str("192.168.1.10").unwrap(),
                    IpAddr::from_str("192.168.1.20").unwrap(),
                )
                .unwrap(),
            ),
            Address::Range(
                IpAddrRange::new(
                    IpAddr::from_str("192.168.1.15").unwrap(),
                    IpAddr::from_str("192.168.1.25").unwrap(),
                )
                .unwrap(),
            ),
        ];
        let result = merge_addrs(&addrs);

        assert_eq!(result.len(), 1);
        if let Address::Range(range) = &result[0] {
            assert_eq!(range.start(), IpAddr::from_str("192.168.1.10").unwrap());
            assert_eq!(range.end(), IpAddr::from_str("192.168.1.25").unwrap());
        } else {
            panic!("Expected Address::Range");
        }
    }

    #[test]
    fn test_merge_addrs_adjacent_ranges() {
        let addrs = vec![
            Address::Range(
                IpAddrRange::new(
                    IpAddr::from_str("192.168.1.10").unwrap(),
                    IpAddr::from_str("192.168.1.20").unwrap(),
                )
                .unwrap(),
            ),
            Address::Range(
                IpAddrRange::new(
                    IpAddr::from_str("192.168.1.21").unwrap(),
                    IpAddr::from_str("192.168.1.30").unwrap(),
                )
                .unwrap(),
            ),
        ];
        let result = merge_addrs(&addrs);

        assert_eq!(result.len(), 1);
        if let Address::Range(range) = &result[0] {
            assert_eq!(range.start(), IpAddr::from_str("192.168.1.10").unwrap());
            assert_eq!(range.end(), IpAddr::from_str("192.168.1.30").unwrap());
        } else {
            panic!("Expected Address::Range");
        }
    }

    #[test]
    fn test_merge_addrs_adjacent_single_addresses() {
        let addrs = vec![
            Address::Network(IpNetwork::from_str("192.168.1.10/32").unwrap()),
            Address::Network(IpNetwork::from_str("192.168.1.11/32").unwrap()),
            Address::Network(IpNetwork::from_str("192.168.1.12/32").unwrap()),
        ];
        let result = merge_addrs(&addrs);

        assert_eq!(result.len(), 1);
        if let Address::Range(range) = &result[0] {
            assert_eq!(range.start(), IpAddr::from_str("192.168.1.10").unwrap());
            assert_eq!(range.end(), IpAddr::from_str("192.168.1.12").unwrap());
        } else {
            panic!("Expected Address::Range");
        }
    }

    #[test]
    fn test_merge_addrs_non_adjacent_ranges() {
        let addrs = vec![
            Address::Range(
                IpAddrRange::new(
                    IpAddr::from_str("192.168.1.10").unwrap(),
                    IpAddr::from_str("192.168.1.20").unwrap(),
                )
                .unwrap(),
            ),
            Address::Range(
                IpAddrRange::new(
                    IpAddr::from_str("192.168.1.30").unwrap(),
                    IpAddr::from_str("192.168.1.40").unwrap(),
                )
                .unwrap(),
            ),
        ];
        let result = merge_addrs(&addrs);

        assert_eq!(result.len(), 2);
        if let Address::Range(range1) = &result[0] {
            assert_eq!(range1.start(), IpAddr::from_str("192.168.1.10").unwrap());
            assert_eq!(range1.end(), IpAddr::from_str("192.168.1.20").unwrap());
        } else {
            panic!("Expected Address::Range");
        }
        if let Address::Range(range2) = &result[1] {
            assert_eq!(range2.start(), IpAddr::from_str("192.168.1.30").unwrap());
            assert_eq!(range2.end(), IpAddr::from_str("192.168.1.40").unwrap());
        } else {
            panic!("Expected Address::Range");
        }
    }

    #[test]
    fn test_merge_addrs_mixed_networks_and_ranges() {
        let addrs = vec![
            Address::Network(IpNetwork::from_str("192.168.1.10/32").unwrap()),
            Address::Range(
                IpAddrRange::new(
                    IpAddr::from_str("192.168.1.11").unwrap(),
                    IpAddr::from_str("192.168.1.15").unwrap(),
                )
                .unwrap(),
            ),
            Address::Network(IpNetwork::from_str("192.168.1.16/32").unwrap()),
        ];
        let result = merge_addrs(&addrs);

        assert_eq!(result.len(), 1);
        if let Address::Range(range) = &result[0] {
            assert_eq!(range.start(), IpAddr::from_str("192.168.1.10").unwrap());
            assert_eq!(range.end(), IpAddr::from_str("192.168.1.16").unwrap());
        } else {
            panic!("Expected Address::Range");
        }
    }

    #[test]
    fn test_merge_addrs_unsorted_input() {
        let addrs = vec![
            Address::Network(IpNetwork::from_str("192.168.1.13/32").unwrap()),
            Address::Network(IpNetwork::from_str("192.168.1.10/32").unwrap()),
            Address::Network(IpNetwork::from_str("192.168.1.12/32").unwrap()),
            Address::Network(IpNetwork::from_str("192.168.1.11/32").unwrap()),
        ];
        let result = merge_addrs(&addrs);

        assert_eq!(result.len(), 1);
        if let Address::Range(range) = &result[0] {
            assert_eq!(range.start(), IpAddr::from_str("192.168.1.10").unwrap());
            assert_eq!(range.end(), IpAddr::from_str("192.168.1.13").unwrap());
        } else {
            panic!("Expected Address::Range");
        }
    }

    #[test]
    fn test_merge_addrs_non_adjacent_singles() {
        let addrs = vec![
            Address::Network(IpNetwork::from_str("192.168.1.20/32").unwrap()),
            Address::Network(IpNetwork::from_str("192.168.1.10/32").unwrap()),
            Address::Network(IpNetwork::from_str("192.168.1.15/32").unwrap()),
            Address::Network(IpNetwork::from_str("192.168.1.11/32").unwrap()),
        ];
        let result = merge_addrs(&addrs);

        // These should result in 3 separate ranges: 10-11, 15, 20
        assert_eq!(result.len(), 3);

        if let Address::Range(range1) = &result[0] {
            assert_eq!(range1.start(), IpAddr::from_str("192.168.1.10").unwrap());
            assert_eq!(range1.end(), IpAddr::from_str("192.168.1.11").unwrap());
        } else {
            panic!("Expected Address::Range");
        }

        if let Address::Range(range2) = &result[1] {
            assert_eq!(range2.start(), IpAddr::from_str("192.168.1.15").unwrap());
            assert_eq!(range2.end(), IpAddr::from_str("192.168.1.15").unwrap());
        } else {
            panic!("Expected Address::Range");
        }

        if let Address::Range(range3) = &result[2] {
            assert_eq!(range3.start(), IpAddr::from_str("192.168.1.20").unwrap());
            assert_eq!(range3.end(), IpAddr::from_str("192.168.1.20").unwrap());
        } else {
            panic!("Expected Address::Range");
        }
    }

    #[test]
    fn test_merge_addrs_ipv6() {
        let addrs = vec![
            Address::Network(IpNetwork::from_str("2001:db8::1/128").unwrap()),
            Address::Network(IpNetwork::from_str("2001:db8::2/128").unwrap()),
            Address::Network(IpNetwork::from_str("2001:db8::3/128").unwrap()),
        ];
        let result = merge_addrs(&addrs);

        assert_eq!(result.len(), 1);
        if let Address::Range(range) = &result[0] {
            assert_eq!(range.start(), IpAddr::from_str("2001:db8::1").unwrap());
            assert_eq!(range.end(), IpAddr::from_str("2001:db8::3").unwrap());
        } else {
            panic!("Expected Address::Range");
        }
    }

    #[test]
    fn test_merge_addrs_contained_ranges() {
        let addrs = vec![
            Address::Range(
                IpAddrRange::new(
                    IpAddr::from_str("192.168.1.10").unwrap(),
                    IpAddr::from_str("192.168.1.30").unwrap(),
                )
                .unwrap(),
            ),
            Address::Range(
                IpAddrRange::new(
                    IpAddr::from_str("192.168.1.15").unwrap(),
                    IpAddr::from_str("192.168.1.20").unwrap(),
                )
                .unwrap(),
            ),
        ];
        let result = merge_addrs(&addrs);

        assert_eq!(result.len(), 1);
        if let Address::Range(range) = &result[0] {
            assert_eq!(range.start(), IpAddr::from_str("192.168.1.10").unwrap());
            assert_eq!(range.end(), IpAddr::from_str("192.168.1.30").unwrap());
        } else {
            panic!("Expected Address::Range");
        }
    }

    #[test]
    fn test_next_ip_ipv4() {
        assert_eq!(
            next_ip(IpAddr::from_str("192.168.1.10").unwrap()),
            IpAddr::from_str("192.168.1.11").unwrap()
        );

        // Test overflow
        assert_eq!(
            next_ip(IpAddr::from_str("255.255.255.255").unwrap()),
            IpAddr::from_str("0.0.0.0").unwrap()
        );
    }

    #[test]
    fn test_next_ip_ipv6() {
        assert_eq!(
            next_ip(IpAddr::from_str("2001:db8::1").unwrap()),
            IpAddr::from_str("2001:db8::2").unwrap()
        );

        // Test overflow
        assert_eq!(
            next_ip(IpAddr::from_str("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff").unwrap()),
            IpAddr::from_str("::").unwrap()
        );
    }

    #[test]
    fn test_merge_addrs_large_gap() {
        let addrs = vec![
            Address::Network(IpNetwork::from_str("192.168.1.1/32").unwrap()),
            Address::Network(IpNetwork::from_str("192.168.1.100/32").unwrap()),
        ];
        let result = merge_addrs(&addrs);

        // Should not merge since there's a large gap
        assert_eq!(result.len(), 2);
        if let Address::Range(range1) = &result[0] {
            assert_eq!(range1.start(), IpAddr::from_str("192.168.1.1").unwrap());
            assert_eq!(range1.end(), IpAddr::from_str("192.168.1.1").unwrap());
        } else {
            panic!("Expected Address::Range");
        }
        if let Address::Range(range2) = &result[1] {
            assert_eq!(range2.start(), IpAddr::from_str("192.168.1.100").unwrap());
            assert_eq!(range2.end(), IpAddr::from_str("192.168.1.100").unwrap());
        } else {
            panic!("Expected Address::Range");
        }
    }
}
