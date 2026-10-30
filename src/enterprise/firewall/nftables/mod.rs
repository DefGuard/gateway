mod monitor;
mod netfilter;

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::atomic::{AtomicU32, Ordering},
};

pub use monitor::ConnectionMonitor;
use monitor::LogTag;
use netfilter::{
    Log, allow_established_traffic, apply_filter_rules, drop_table, ignore_unrelated_traffic,
    init_firewall, log_inbound_traffic, send_batch, set_nat_rules,
};
use nftnl::Batch;

use super::{
    Address, FirewallError, FirewallRule, Policy, Port, Protocol, SnatBinding,
    api::{FirewallApi, FirewallManagementApi},
    iprange::IpAddrRangeError,
    monitor::TrafficDirection,
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
    // Send matching packets to the connection monitor.
    log: Option<Log>,
}

/// Merges any contiguous subets or addres ranges into an address range.
///
/// This reflects the way `nft` CLI handles such cases.
/// Otherwise first address in any subnet after the first is not matched.
/// For example if we use `172.30.0.2/31, 172.30.0.4/31` as `saddr` in a rule,
/// then 172.30.0.4 will not be matched.
fn merge_addrs(addrs: Vec<Address>) -> Result<Vec<Address>, IpAddrRangeError> {
    debug!("Merging any contiguous subnets and ranges found within address list: {addrs:?}");

    if addrs.is_empty() {
        debug!("No addresses provided, returning empty vector.");
        return Ok(Vec::new());
    }

    let mut merged_addrs = Vec::new();
    let mut current_address = None;

    // we can assume addresses coming from the core
    // are already sorted and non-overlapping
    for next_address in addrs {
        match &current_address {
            None => {
                debug!("Initializing current address with: {next_address:?}");
                current_address = Some(next_address);
            }
            Some(previous_address) => {
                let previous_range_start = previous_address.first();
                let previous_range_end = previous_address.last();
                let next_ip = next_ip(previous_range_end);

                let next_range_start = next_address.first();
                let next_range_end = next_address.last();

                // check if range is adjacent to current address
                if next_range_start == next_ip {
                    // replace current address with a combined range
                    debug!("Merging {next_address:?} with {current_address:?}");
                    current_address = Some(Address::Range(IpAddrRange::new(
                        previous_range_start,
                        next_range_end,
                    )?));
                } else {
                    // push previous address to result and replace with next address
                    merged_addrs.push(previous_address.clone());
                    current_address = Some(next_address);
                }
            }
        }
    }

    // push last remaining address to results
    if let Some(address) = current_address {
        debug!("Pushing last remaining address into results: {address:?}");
        merged_addrs.push(address);
    }

    debug!("Prepared addresses: {merged_addrs:?}");

    Ok(merged_addrs)
}

/// Returns the next IP address in sequence, handling overflow via wrapping
fn next_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(ipv4) => {
            let ip_u32 = ipv4.to_bits();
            let next_ip_u32 = ip_u32.wrapping_add(1);
            IpAddr::V4(Ipv4Addr::from(next_ip_u32))
        }
        IpAddr::V6(ipv6) => {
            let ip_u128 = ipv6.to_bits();
            let next_ip_u128 = ip_u128.wrapping_add(1);
            IpAddr::V6(Ipv6Addr::from(next_ip_u128))
        }
    }
}

impl FirewallApi {
    fn add_rule(&mut self, rule: &FirewallRule) -> Result<(), FirewallError> {
        debug!("Applying the following Defguard ACL rule: {rule:?}");

        let mut filter_rules = Vec::new();
        debug!(
            "The rule will be split into multiple nftables rules based on the specified \
            destination ports and protocols."
        );

        let source_addrs = merge_addrs(rule.source_addrs.clone())?;
        let dest_addrs = merge_addrs(rule.destination_addrs.clone())?;
        let log = Log::new(
            &self.ifname,
            LogTag {
                direction: TrafficDirection::Outbound,
                verdict: rule.verdict,
                rule_id: Some(rule.id),
            },
        );

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
                log: Some(log.clone()),
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
                let mut filter_rule = FilterRule {
                    src_ips: &source_addrs,
                    dest_ips: &dest_addrs,
                    protocols: vec![protocol],
                    action: rule.verdict,
                    counter: true,
                    defguard_rule_id: rule.id,
                    v4: rule.ipv4,
                    comment: rule.comment.clone(),
                    log: Some(log.clone()),
                    ..Default::default()
                };
                if protocol.supports_ports() {
                    debug!("Protocol supports ports, rule.");
                    filter_rule.dest_ports = &rule.destination_ports;
                } else {
                    debug!(
                        "Protocol does not support ports, applying nftables rule and ignoring \
                        destination ports."
                    );
                }
                filter_rules.push(filter_rule);
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
                    log: Some(log.clone()),
                    ..Default::default()
                };
                filter_rules.push(rule);
            }
        }

        apply_filter_rules(&filter_rules, &self.ifname, &self.socket)?;

        debug!(
            "Applied firewall rules for Defguard ACL rule ID: {}",
            rule.id
        );
        Ok(())
    }
}

impl FirewallManagementApi for FirewallApi {
    /// Sets up the firewall with the given default policy and priority. Drops the previous table.
    fn setup(
        &mut self,
        default_policy: Policy,
        priority: Option<i32>,
    ) -> Result<(), FirewallError> {
        debug!("Initializing firewall, VPN interface: {}", self.ifname);
        self.default_policy = default_policy;
        let mut batch = Batch::new();
        drop_table(&mut batch, &self.ifname);
        init_firewall(default_policy, priority, &mut batch, &self.ifname);
        debug!("Allowing all established traffic");
        log_inbound_traffic(&mut batch, &self.ifname)?;
        ignore_unrelated_traffic(&mut batch, &self.ifname)?;
        allow_established_traffic(&mut batch, &self.ifname)?;
        send_batch(&batch.finalize(), &self.socket)?;
        debug!("Allowed all established traffic");
        debug!("Initialized firewall");

        Ok(())
    }

    /// Cleans up the whole Defguard table.
    fn cleanup(&mut self) -> Result<(), FirewallError> {
        debug!("Cleaning up all previous firewall rules, if any");
        let mut batch = Batch::new();
        drop_table(&mut batch, &self.ifname);
        send_batch(&batch.finalize(), &self.socket)?;

        debug!("Cleaned up all previous firewall rules");
        Ok(())
    }

    fn setup_nat(
        &mut self,
        masquerade_enabled: bool,
        snat_bindings: &[SnatBinding],
    ) -> Result<(), FirewallError> {
        debug!(
            "Setting up POSTROUTING chain rules with masquerade status: {masquerade_enabled} and \
            SNAT bindings: {snat_bindings:?}"
        );

        let mut batch = Batch::new();
        set_nat_rules(&mut batch, &self.ifname, masquerade_enabled, snat_bindings)?;
        send_batch(&batch.finalize(), &self.socket)?;

        debug!("Finished POSTROUTING chain rules setup");
        Ok(())
    }

    fn add_rules(&mut self, rules: &[FirewallRule]) -> Result<(), FirewallError> {
        debug!("Applying the following Defguard ACL rules: {rules:?}");
        for rule in rules {
            self.add_rule(rule)?;
        }
        // Explicitly apply the default policy at the end of the chain, so connections which did
        // not match any rule are reported to the connection monitor.
        let default_rule = FilterRule {
            action: self.default_policy,
            counter: true,
            comment: Some("Default policy".to_string()),
            log: Some(Log::new(
                &self.ifname,
                LogTag {
                    direction: TrafficDirection::Outbound,
                    verdict: self.default_policy,
                    rule_id: None,
                },
            )),
            ..Default::default()
        };
        apply_filter_rules(&[default_rule], &self.ifname, &self.socket)?;
        debug!("Applied all Defguard ACL rules");
        Ok(())
    }
}

#[cfg(test)]
mod tests;
